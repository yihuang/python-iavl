import itertools
from collections.abc import Iterator
from typing import Optional

import cprotobuf
import rocksdb


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


class CommitID(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    hash = cprotobuf.Field("bytes", 2)


class StoreInfo(cprotobuf.ProtoEntity):
    name = cprotobuf.Field("string", 1)
    commit_id = cprotobuf.Field(CommitID, 2)


class CommitInfo(cprotobuf.ProtoEntity):
    version = cprotobuf.Field("int64", 1)
    store_infos = cprotobuf.Field(StoreInfo, 2, repeated=True)
