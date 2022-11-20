import binascii
import mmap
import sys
from pathlib import Path

import click

from .archive import bisect
from .archive import dump_hashes as _dump_hashes
from .archive import eval_dict as _eval_dict
from .archive import train_dict as _train_dict


@click.group
def cli():
    pass


@cli.command()
@click.option("--output", "-o", help="output file path", default="-")
@click.argument("store")
def dump_hashes(store, output):
    """
    iterate iavl tree nodes and dump the node hashes into a file
    """
    if output == "-":
        _dump_hashes(store, sys.stdout.buffer)
    else:
        with open(output, "wb") as fp:
            _dump_hashes(store, fp)


@cli.command()
@click.argument("hash-file")
@click.argument("target")
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
        print(bisect(buf, target, count))


@cli.command()
@click.option("--output", "-o", help="output file path", default="-")
@click.option("--dict-size", help="target dictionary size", default=110 * 1024)
@click.argument("hash-file")
@click.argument("store")
def train_dict(hash_file: str, store: str, output: str, dict_size):
    """
    sample node values to train compression dict
    """
    hash_file = Path(hash_file)
    if output == "-":
        _train_dict(hash_file, store, sys.stdout.buffer, dict_size)
    else:
        with open(output, "wb") as fp:
            _train_dict(hash_file, store, fp, dict_size)


@cli.command()
@click.option("--samples", help="the number of node values to sample", default=10000)
@click.option("--level", help="compression level to evaluate", default=3)
@click.argument("hash-file")
@click.argument("dict-file")
@click.argument("store")
def eval_dict(hash_file: str, dict_file: str, store: str, samples: int, level: int):
    """
    Evaluate compression ratio of the dictionary
    """
    size, compressed_size, compressed_size_with_dict = _eval_dict(
        Path(hash_file), store, Path(dict_file), level, samples
    )
    print(f"uncompressed size: {size}")
    print(f"compressed size with dict: {compressed_size}")
    print(f"compressed size without dict: {compressed_size_with_dict}")


if __name__ == "__main__":
    cli()
