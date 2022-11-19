import binascii
import mmap
import os
import random
import sys
from pathlib import Path
from typing import Optional

import click
import pyzstd

import rocksdb


@click.group
def cli():
    pass


def _dump_hashes(store, output):
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    prefix = f"s/k:{store}/".encode() + b"n"
    it = db.iterkeys()
    it.seek(prefix)
    prefix_len = len(prefix)
    for k in it:
        if not k.startswith(prefix):
            break
        assert 32 == output.write(k[prefix_len:])


@cli.command()
@click.option("--output/-o", "output file path", default="-")
@click.argument("store")
def dump_hashes(store, output):
    if output == "-":
        _dump_hashes(store, sys.stdout)
    else:
        with open(output) as fp:
            _dump_hashes(store, fp)


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


@cli.command()
@click.argument("hash-file")
@click.argument("store")
def search_node(hash_file: str, target: str):
    """
    search node index by hash in node hash file
    """
    hash_file = Path(hash_file)
    target = binascii.unhexlify(target)
    assert hash_file.stat().st_size % 32 == 0
    count = hash_file.stat().st_size // 32
    with hash_file.open() as fp:
        buf = mmap.mmap(fp.fileno(), length=0, access=mmap.ACCESS_READ)
        return bisect(buf, target, count)


@cli.command()
@click.argument("hash-file")
@click.argument("store")
def train_dict(hash_file: str, store: str):
    """
    sample node values to train compression dict
    """
    hash_file = Path(hash_file)
    prefix = f"s/k:{store}/".encode() + b"n"
    dsize = 110 * 1024
    target_size = dsize * 1024
    db = rocksdb.DB(os.environ["DB"], rocksdb.Options(), read_only=True)
    visited = set()
    sample_size = 0
    samples = []
    count = hash_file.stat().st_size // 32
    with hash_file.open() as fp:
        buf = mmap.mmap(fp.fileno(), length=0, access=mmap.ACCESS_READ)
        while sample_size < target_size and len(visited) < count:
            i = random.randint(0, count - 1)
            if i in visited:
                continue
            offset = i * 32
            visited.add(offset)
            hash = buf[offset : offset + 32]
            assert len(hash) == 32
            value = db.get(prefix + hash)
            samples.append(value)
            sample_size += len(value)
    sys.stdout.buffer.write(pyzstd.train_dict(samples, dsize).dict_content)


@cli.command()
@click.argument("dict-file")
@click.argument("store")
def eval_dict(hash_file: Path, store: str):
    """
    Evaluate compression ratio of the dictionary
    """
    pass


if __name__ == "__main__":
    cli()
