import hashlib
import itertools
from collections.abc import Iterator
from typing import Callable, List, NamedTuple, Optional, Tuple

import cprotobuf
from hexbytes import HexBytes

from .dbm import DBM

EMPTY_HASH = hashlib.sha256().digest()
GetNode = Callable[bytes, Optional["PersistedNode"]]


class CommitID(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    hash = cprotobuf.Field("bytes", 2)


class StoreInfo(cprotobuf.ProtoEntity):
    name = cprotobuf.Field("string", 1)
    commit_id = cprotobuf.Field(CommitID, 2)


class CommitInfo(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    store_infos = cprotobuf.Field(StoreInfo, 2, repeated=True)


class StdInt(cprotobuf.ProtoEntity):
    value = cprotobuf.Field("uint64", 1)


class PersistedNode(NamedTuple):
    """
    immutable nodes that's loaded from and save to db
    """

    height: int  # height of subtree
    size: int  # size of subtree
    version: int  # the version created at
    key: bytes

    # only in leaf node
    value: Optional[bytes]

    # only in branch nodes
    left_node_ref: Optional[bytes]
    right_node_ref: Optional[bytes]

    hash: bytes

    def is_leaf(self):
        return self.height == 0

    def left_node(self, ndb):
        if self.left_node_ref is not None:
            return ndb.get(self.left_node_ref)

    def right_node(self, ndb):
        if self.right_node_ref is not None:
            return ndb.get(self.right_node_ref)

    def as_json(self):
        d = self._asdict()
        d["key"] = HexBytes(self.key).hex()
        if self.value is not None:
            d["value"] = HexBytes(self.value).hex()
        if self.left_node_ref is not None:
            d["left_node_ref"] = HexBytes(self.left_node_ref).hex()
        if self.right_node_ref is not None:
            d["right_node_ref"] = HexBytes(self.right_node_ref).hex()
        if self.hash is not None:
            d["hash"] = HexBytes(self.hash).hex()
        return d

    def encode(self):
        return encode_node(self)

    def calc_balance(self, ndb):
        return self.left_node(ndb).height - self.right_node(ndb).height

    @staticmethod
    def decode(bz: bytes, hash: bytes):
        nd, _ = decode_node(bz, hash)
        return nd


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
    if not s:
        return b""
    return b"s/k:%s/" % s.encode()


def prev_version(db: DBM, store: str, v: int) -> Optional[int]:
    it = reversed(db.iterkeys())
    prefix = store_prefix(store) if store is not None else b""
    target = prefix + root_key(v)
    it.seek(target)
    k = next(it, None)
    if k is None:
        it.seek_to_last()
        k = next(it, None)
    if k is None:
        # empty db
        return
    if k >= target:
        k = next(it)
    if not k.startswith(prefix + b"r"):
        return
    # parse version from key
    return int.from_bytes(k[len(prefix) + 1 :], "big")


def iavl_latest_version(db: DBM, store: str) -> Optional[int]:
    return prev_version(db, store, 1 << 63 - 1)


def decode_bytes(bz: bytes) -> (bytes, int):
    l, n = cprotobuf.decode_primitive(bz, "uint64")
    assert l + n <= len(bz)
    return bz[n : n + l], n + l


def encode_bytes(bz: bytes) -> List[bytes]:
    return [
        cprotobuf.encode_primitive("uint64", len(bz)),
        bz,
    ]


def encode_node(node: PersistedNode) -> bytes:
    chunks = [
        cprotobuf.encode_primitive("sint64", node.height),
        cprotobuf.encode_primitive("sint64", node.size),
        cprotobuf.encode_primitive("sint64", node.version),
    ] + encode_bytes(node.key)
    if node.is_leaf():
        chunks += encode_bytes(node.value)
    else:
        chunks += encode_bytes(node.left_node_ref) + encode_bytes(node.right_node_ref)
    return b"".join(chunks)


def decode_node(bz: bytes, hash: bytes) -> (PersistedNode, int):
    offset = 0
    height, n = cprotobuf.decode_primitive(bz[offset:], "sint64")
    offset += n
    size, n = cprotobuf.decode_primitive(bz[offset:], "sint64")
    offset += n
    version, n = cprotobuf.decode_primitive(bz[offset:], "sint64")
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
    return (
        PersistedNode(
            height=height,
            size=size,
            version=version,
            key=key,
            value=value,
            left_node_ref=left_hash,
            right_node_ref=right_hash,
            hash=hash,
        ),
        offset,
    )


def decode_fast_node(bz: bytes) -> (int, bytes, int):
    offset = 0
    version, n = cprotobuf.decode_primitive(bz[offset:], "sint64")
    offset += n
    value, n = decode_bytes(bz[offset:])
    offset += n
    return version, value, offset


def get_node(
    db: DBM, hash: bytes, store: Optional[str] = None
) -> Optional[PersistedNode]:
    prefix = store_prefix(store) if store is not None else b""
    bz = db.get(prefix + node_key(hash))
    if not bz:
        return
    node, _ = decode_node(bz, hash)
    return node


def get_root_node(
    db: DBM, version: int, store: Optional[str] = None
) -> Optional[PersistedNode]:
    prefix = store_prefix(store) if store is not None else b""
    hash = db.get(prefix + root_key(version))
    if not hash:
        return
    return get_node(db, hash, store)


def iter_fast_nodes(db: DBM, store: str, start: Optional[bytes], end: Optional[bytes]):
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
        _, value, _ = decode_fast_node(v)
        yield k, value


def within_range(key: bytes, start: Optional[bytes], end: Optional[bytes]):
    """
    start is inclusive, end is exclusive
    """
    return (start is None or key >= start) and (end is None or key < end)


def iter_iavl_tree(
    db: DBM,
    store: Optional[str],
    node_hash: bytes,
    start: Optional[bytes],
    end: Optional[bytes],
):
    if not node_hash or node_hash == EMPTY_HASH:
        # empty root node
        return

    prefix = store_prefix(store) if store is not None else b""

    def get_node(hash: bytes) -> PersistedNode:
        n, _ = decode_node(db.get(prefix + node_key(hash)), hash)
        return n

    def prune_check(node: PersistedNode) -> (bool, bool):
        prune_left = start is not None and node.key <= start
        prune_right = end is not None and node.key >= end
        return prune_left, prune_right

    for node in visit_iavl_nodes(get_node, prune_check, node_hash):
        if node.is_leaf() and within_range(node.key, start, end):
            yield node.key, node.value


def visit_iavl_nodes(
    get_node: GetNode,
    prune_check: Callable[PersistedNode, Tuple[bool, bool]],
    hash: bytes,
    preorder: bool = True,
):
    """
    tree traversal, preorder or postorder

    get_node: load node by hash.
    prune_check: decide should we prune left child and right child
    """
    stack: List[bytes] = [hash]
    while stack:
        hash_or_node = stack.pop()
        if isinstance(hash_or_node, PersistedNode):
            # the postorder case, it's already expanded as PersistedNode
            yield hash_or_node
            continue

        node = get_node(hash_or_node)

        if not preorder:
            # postorder, visit later
            stack.append(node)

        if not node.is_leaf():
            prune_left, prune_right = prune_check(node)
            if not prune_right:
                stack.append(node.right_node_ref)
            if not prune_left:
                stack.append(node.left_node_ref)

        if preorder:
            yield node


def diff_iterators(it1, it2):
    """
    yield: (status, key, value)
    status:
      - 0: value difference
      - 1: new key on the left
      - 2: new key on the right
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
        elif k2 is None:
            action = 1
            yield 1, k1, v1
        elif k1 is None:
            action = 2
            yield 2, k2, v2
        elif k1 == k2:
            if v1 != v2:
                yield 0, k1, (v1, v2)
            action = 0
        elif k1 < k2:
            action = 1
            yield 1, k1, v1
        else:
            action = 2
            yield 2, k2, v2


def multistore_latest_version(db: DBM) -> int:
    bz = db.get(b"s/latest")
    version, _ = cprotobuf.decode_primitive(bz[1:], "uint64")
    return version


def load_commit_infos(db: DBM, version: Optional[int] = None) -> CommitInfo:
    if version is None:
        version = multistore_latest_version(db)
    bz = db.get(f"s/{version}".encode())
    res = CommitInfo()
    res.ParseFromString(bz)
    assert version == res.version
    return res


def decode_stdint(bz: bytes) -> int:
    o = StdInt()
    o.ParseFromString(bz)
    return o.value


def encode_stdint(n: int) -> bytes:
    o = StdInt()
    o.value = n
    return bytes(o.SerializeToString())


class KVPair(cprotobuf.ProtoEntity):
    delete = cprotobuf.Field("bool", 1)
    key = cprotobuf.Field("bytes", 2)
    value = cprotobuf.Field("bytes", 3)


class ChangeSet(cprotobuf.ProtoEntity):
    pairs = cprotobuf.Field(KVPair, 1, repeated=True)
