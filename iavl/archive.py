import itertools
import mmap
import os
import random
import sys
from pathlib import Path
from typing import Optional

import pyzstd

import rocksdb


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


def train_dict(hash_file: Path, store: str, output):
    prefix = f"s/k:{store}/".encode() + b"n"
    dsize = 110 * 1024
    target_size = dsize * 1024
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
    compression_dict: Path,
    compression_level: int,
    sample_size: int,
):
    prefix = f"s/k:{store}/".encode() + b"n"
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    d = pyzstd.ZstdDict(compression_dict.read_bytes())

    size = 0
    compressed_size = 0
    compressed_size_with_dict = 0
    for hash in itertools.islice(sample_node_hashes(hash_file), sample_size):
        v = db.get(prefix + hash)
        size += len(v)
        compressed = pyzstd.compress(v, compression_level, zstd_dict=d)
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


def dump_hashes(store, output):
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    prefix = f"s/k:{store}/".encode() + b"n"
    it = db.iterkeys()
    it.seek(prefix)
    prefix_len = len(prefix)
    for k in it:
        if not k.startswith(prefix):
            break
        assert 32 == output.write(k[prefix_len:])
