import itertools
import mmap
import os
import random
from pathlib import Path
from typing import Optional

import lz4.frame
import pyzstd
import roaring64
from cprotobuf import decode_primitive, encode_primitive

import rocksdb

from .utils import Node, decode_bytes, decode_node, encode_bytes, store_prefix


def iter_node_hashes(hash_file: Path):
    filesize = hash_file.stat().st_size
    assert filesize % 32 == 0
    count = filesize // 32
    with hash_file.open("rb") as fp:
        buf = mmap.mmap(fp.fileno(), length=0, access=mmap.ACCESS_READ)
        for i in range(count):
            offset = i * 32
            yield buf[offset : offset + 32]


def sample_node_hashes(hash_file: Path):
    filesize = hash_file.stat().st_size
    assert filesize % 32 == 0
    count = filesize // 32
    visited = set()
    with hash_file.open("rb") as fp:
        buf = mmap.mmap(fp.fileno(), length=0, access=mmap.ACCESS_READ)
        while len(visited) < count:
            i = random.randint(0, count - 1)
            if i in visited:
                continue
            visited.add(i)
            offset = i * 32
            yield buf[offset : offset + 32]


def train_dict(hash_file: Path, store: str, output, dsize: int = 110 * 1024):
    prefix = f"s/k:{store}/".encode() + b"n"
    target_size = dsize * 100
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    sample_size = 0

    samples = []
    for hash in sample_node_hashes(hash_file):
        v = db.get(prefix + hash)
        samples.append(v)
        sample_size += len(v)
        if sample_size >= target_size:
            break
    output.write(pyzstd.train_dict(samples, dsize).dict_content)


def eval_dict(
    hash_file: Path,
    store: str,
    compression_type: str,
    compression_dict: Path,
    compression_level: int,
    sample_size: int,
):
    prefix = store_prefix(store) + b"n"
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    d = pyzstd.ZstdDict(compression_dict.read_bytes())

    size = 0
    compressed_size = 0
    compressed_size_with_dict = 0
    for hash in itertools.islice(sample_node_hashes(hash_file), sample_size):
        v = db.get(prefix + hash)
        size += len(v)
        if compression_type == "zstd":
            compressed = pyzstd.compress(v, compression_level, zstd_dict=d)
        elif compression_type == "lz4":
            compressed = lz4.frame.compress(
                v, compression_level=compression_level, zstd_dict=d
            )
        compressed_size += len(compressed)
        compressed = pyzstd.compress(v, compression_level)
        compressed_size_with_dict += len(compressed)
    return size, compressed_size, compressed_size_with_dict


def bisect(buf, target: bytes, hi, lo=0) -> Optional[int]:
    while lo < hi:
        mid = (lo + hi) // 2
        offset = mid * 32
        if target <= buf[offset : offset + 32]:
            hi = mid
        else:
            lo = mid + 1

    offset = lo * 32
    if target == buf[offset : offset + 32]:
        return lo


def dump_hashes(store, output, output_leaf_bitmap: Optional[str] = None):
    if output_leaf_bitmap:
        bm = roaring64.BitMap64()
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    prefix = store_prefix(store) + b"n"
    if output_leaf_bitmap:
        it = db.iteritems()
    else:
        it = db.iterkeys()
    it.seek(prefix)
    prefix_len = len(prefix)
    for i, k in enumerate(it):
        if output_leaf_bitmap:
            k, v = k
            if v[0] == 0:
                # is leaf node
                bm.add(i)
        if not k.startswith(prefix):
            break
        assert 32 == output.write(k[prefix_len:])
    if output_leaf_bitmap:
        Path(output_leaf_bitmap).write_bytes(bm.serialize())


def encode_branch_node2(
    height, size, version, key, left_node_index, right_node_index
) -> bytes:
    chunks = (
        [
            encode_primitive("sint64", height),
            encode_primitive("sint64", size),
            encode_primitive("sint64", version),
        ]
        + encode_bytes(key)
        + [
            encode_primitive("int64", left_node_index),
            encode_primitive("int64", right_node_index),
        ]
    )
    return b"".join(chunks)


def decode_node2(bz: bytes, hash_buf: bytes) -> (Node, int):
    offset = 0
    height, n = decode_primitive(bz[offset:], "sint64")
    offset += n
    size, n = decode_primitive(bz[offset:], "sint64")
    offset += n
    version, n = decode_primitive(bz[offset:], "sint64")
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
        left_index, n = decode_primitive(bz[offset:], "int64")
        offset += n
        right_index, n = decode_primitive(bz[offset:], "int64")
        offset += n

        tmp = left_index * 32
        left_hash = hash_buf[tmp : tmp + 32]
        tmp = right_index * 32
        right_hash = hash_buf[tmp : tmp + 32]
    return (
        Node(
            height=height,
            size=size,
            version=version,
            key=key,
            value=value,
            left_node_ref=left_hash,
            right_node_ref=right_hash,
        ),
        offset,
    )


def dump_nodes(
    hash_file: Path,
    store,
    output,
    offset_output: Path,
):
    """
    dump node values without compression
    - replace children keys with node index
    """
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    prefix = store_prefix(store) + b"n"
    offset = 0
    m = roaring64.BitMap64()
    with hash_file.open() as fp:
        buf = mmap.mmap(fp.fileno(), length=0, access=mmap.ACCESS_READ)
        count = len(buf) // 32
        for i in range(count):
            tmp = i * 32
            hash = buf[tmp : tmp + 32]
            v = db.get(prefix + hash)
            node, _ = decode_node(v)
            if not node.is_leaf():
                left_node_index = bisect(buf, node.left_node_ref, count)
                right_node_index = bisect(buf, node.left_node_ref, count)
                v = encode_branch_node2(
                    node.height,
                    node.size,
                    node.version,
                    node.key,
                    left_node_index,
                    right_node_index,
                )
            m.add(offset)
            assert len(v) == output.write(v)
            offset += len(v)
    offset_output.write_bytes(m.serialize())


def dump_leaf_bitmap(store: str, output):
    """
    dump a bitmap with leaf node index set to 1
    """
    bm = roaring64.BitMap64()
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    prefix = store_prefix(store) + b"n"
    it = db.iteritems()
    it.seek(prefix)
    for i, (k, v) in enumerate(it):
        if not k.startswith(prefix):
            break
        if v[0] == 0:
            # leaf node
            bm.add(i)
    output.write(bm.serialize())
