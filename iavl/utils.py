import itertools
from collections.abc import Iterator
from typing import Callable, List, NamedTuple, Optional, Tuple

import cprotobuf
import rocksdb
from hexbytes import HexBytes


class CommitID(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    hash = cprotobuf.Field("bytes", 2)


class StoreInfo(cprotobuf.ProtoEntity):
    name = cprotobuf.Field("string", 1)
    commit_id = cprotobuf.Field(CommitID, 2)


class CommitInfo(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    store_infos = cprotobuf.Field(StoreInfo, 2, repeated=True)


class Node(NamedTuple):
    height: int  # height of subtree
    size: int  # size of subtree
    version: int
    key: bytes
    value: Optional[bytes]
    left_child: Optional[bytes]
    right_child: Optional[bytes]

    def is_leaf(self):
        return self.height == 0

    def as_json(self):
        d = self._asdict()
        d["key"] = HexBytes(self.key).hex()
        if self.value is not None:
            d["value"] = HexBytes(self.value).hex()
        if self.left_child is not None:
            d["left_child"] = HexBytes(self.left_child).hex()
        if self.right_child is not None:
            d["right_child"] = HexBytes(self.right_child).hex()
        return d


def incr_bytes(prefix: bytes) -> bytes:
    bz = list(prefix)
    while bz:
        if bz[-1] != 255:
            bz[-1] += 1
            break

        bz = bz[:-1]
    return bytes(bz)


def prefix_iterkeys(
    it: Iterator, prefix: bytes, reverse: bool = False, end: Optional[bytes] = None
):
    if not reverse:
        end = incr_bytes(prefix) if not end else prefix + end
        it = itertools.takewhile(lambda t: t < end, it)
    else:
        if end:
            it = itertools.takewhile(lambda t: t > prefix + end, it)
        else:
            it = itertools.takewhile(lambda t: t >= prefix, it)
    return (k.removeprefix(prefix) for k in it)


def prefix_iteritems(
    it: Iterator, prefix: bytes, reverse: bool = False, end: Optional[bytes] = None
):
    if not reverse:
        end = incr_bytes(prefix) if not end else prefix + end
        it = itertools.takewhile(lambda t: t[0] < end, it)
    else:
        if end:
            it = itertools.takewhile(lambda t: t[0] > prefix + end, it)
        else:
            it = itertools.takewhile(lambda t: t[0] >= prefix, it)
    return ((k.removeprefix(prefix), v) for k, v in it)


def root_key(v: int) -> bytes:
    return b"r" + v.to_bytes(8, "big")


def node_key(hash: bytes) -> bytes:
    return b"n" + hash


def fast_node_key(key: bytes) -> bytes:
    return b"f" + key


def store_prefix(s: str) -> bytes:
    return b"s/k:%s/" % s.encode()


def prev_version(db: rocksdb.DB, store: str, v: int) -> Optional[int]:
    it = db.iterkeys()
    prefix = store_prefix(store)
    it.seek_for_prev(prefix + root_key(v))
    try:
        k = next(it)
    except StopIteration:
        return
    else:
        if not k.startswith(prefix + b"r"):
            return
        # parse version from key
        return int.from_bytes(k[len(prefix) + 1 :], "big")


def iavl_latest_version(db: rocksdb.DB, store: str) -> int:
    return prev_version(db, store, 1 << 63 - 1)


def decode_bytes(bz: bytes) -> (bytes, int):
    l, n = cprotobuf.decode_primitive(bz, "uint64")
    assert l + n <= len(bz)
    return bz[n : n + l], n + l


def decode_node(bz: bytes) -> (Node, int):
    offset = 0
    height, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    size, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    version, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    key, n = decode_bytes(bz[offset:])
    offset += n

    value = left_hash = right_hash = None

    if height == 0:
        # leaf node, read value
        value, n = decode_bytes(bz[offset:])
        offset += n
    else:
        # container node, read children
        left_hash, n = decode_bytes(bz[offset:])
        offset += n
        right_hash, n = decode_bytes(bz[offset:])
        offset += n
    return Node(height, size, version, key, value, left_hash, right_hash), offset


def decode_fast_node(bz: bytes) -> (int, bytes, int):
    offset = 0
    version, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    value, n = decode_bytes(bz[offset:])
    offset += n
    return version, value, offset


def iter_fast_nodes(
    db: rocksdb.DB, store: str, start: Optional[bytes], end: Optional[bytes]
):
    """
    normal kv db iteration
    end is exclusive if provided.
    """
    it = db.iteritems()

    prefix = store_prefix(store) + b"f"
    if start is None:
        start = prefix
    else:
        start = prefix + start

    it.seek(start)

    for k, v in it:
        if not k.startswith(prefix):
            break
        k = k.removeprefix(prefix)
        if end is not None and k >= end:
            break
        yield k, v


def within_range(key: bytes, start: Optional[bytes], end: Optional[bytes]):
    """
    start is inclusive, end is exclusive
    """
    return (start is None or key >= start) and (end is None or key < end)


def iter_iavl_tree(
    db: rocksdb.DB,
    store: str,
    node_hash: bytes,
    start: Optional[bytes],
    end: Optional[bytes],
):
    prefix = store_prefix(store)

    def get_node(hash: bytes) -> Node:
        n, _ = decode_node(db.get(prefix + node_key(hash)))
        return n

    def prune_check(key: bytes) -> (bool, bool):
        prune_left = start is not None and key <= start
        prune_right = end is not None and key >= end
        return prune_left, prune_right

    for node in visit_iavl_nodes(get_node, prune_check, node_hash):
        if node.is_leaf() and within_range(node.key, start, end):
            yield node.key, node.value


def visit_iavl_nodes(
    get_node: Callable[bytes, Node],
    prune_check: Callable[bytes, Tuple[bool, bool]],
    hash: bytes,
):
    """
    get_node: load node by hash.
    prune_check: decide should we prune left child and right child
    """
    stack: List[bytes] = [hash]
    while stack:
        node = get_node(stack.pop())
        if not node.is_leaf():
            prune_left, prune_right = prune_check(node.key)
            if not prune_right:
                stack.append(node.right_child)
            if not prune_left:
                stack.append(node.left_child)

        # preorder traversal
        yield node


def diff_iterators(it1, it2):
    """
    yield: (left_or_right, key, value)
    """
    # 0: advance both
    # 1: advance it1
    # 2: advance it2
    action = 0
    while True:
        if action in (0, 1):
            k1, v1 = next(it1, (None, None))
        if action in (0, 2):
            k2, v2 = next(it2, (None, None))

        if k1 is None and k2 is None:
            break
        elif k1 == k2:
            action = 0
        elif k2 is None:
            action = 1
            yield True, k1, v1
        elif k1 is None:
            action = 2
            yield False, k2, v2
        elif k1 < k2:
            action = 1
            yield True, k1, v1
        else:
            action = 2
            yield False, k2, v2
