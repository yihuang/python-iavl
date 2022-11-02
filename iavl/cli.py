import binascii
from typing import List, Optional

import click
import cprotobuf
import rocksdb
from hexbytes import HexBytes


def root_key(v: int) -> bytes:
    return b"r" + v.to_bytes(8, "big")


def node_key(hash: bytes) -> bytes:
    return b"n" + hash


def fast_node_key(key: bytes) -> bytes:
    return b"f" + key


def store_prefix(s: str) -> bytes:
    return b"s/k:%s/" % s.encode()


def prev_version(db: rocksdb.DB, store: str, v: int) -> int:
    it = db.iterkeys()
    prefix = store_prefix(store)
    it.seek_for_prev(prefix + root_key(v))
    try:
        k = next(it)
    except StopIteration:
        return None
    else:
        # parse version from key
        return int.from_bytes(k[len(prefix) + 1 :], "big")


def latest_version(db: rocksdb.DB, store: str) -> int:
    return prev_version(db, store, 1 << 63 - 1)


def decode_bytes(bz: bytes) -> (bytes, int):
    l, n = cprotobuf.decode_primitive(bz, "uint64")
    assert l + n <= len(bz)
    return bz[n : n + l], n + l


@click.group
def cli():
    pass


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option(
    "--version",
    help="the version to query, default to latest version if not provided",
    type=click.INT,
)
@click.option("--store", "-s", multiple=True)
def root_hash(db, store: List[str], version: Optional[int]):
    """
    print hashes of iavl stores
    """
    if not store:
        raise click.UsageError("no store names are provided")
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        if version is None:
            version = latest_version(db, s)
        bz = db.get(store_prefix(s) + root_key(version))
        print(f"{s}: {binascii.hexlify(bz).decode()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.argument("hash")
def node(db, hash, store):
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    bz = db.get(store_prefix(store) + node_key(HexBytes(hash)))
    offset = 0
    height, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    size, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    version, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    key, n = decode_bytes(bz[offset:])
    offset += n

    print(
        f"height: {height}, size: {size}, version: {version}, "
        f"key: {HexBytes(key).hex()}, ",
        end="",
    )
    if height == 0:
        # leaf node, read value
        value, n = decode_bytes(bz[offset:])
        offset += n
        print(f"value: {HexBytes(value).hex()}")
    else:
        # container node, read children
        left_hash, n = decode_bytes(bz[offset:])
        offset += n
        right_hash, n = decode_bytes(bz[offset:])
        offset += n
        print(
            f"left hash: {HexBytes(left_hash).hex()}, "
            f"right hash: {HexBytes(right_hash).hex()}"
        )


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.argument("key")
def fast_node(db, key, store):
    if not store:
        raise click.UsageError("no store names are provided")
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    bz = db.get(store_prefix(store) + fast_node_key(HexBytes(key)))
    offset = 0
    version, n = cprotobuf.decode_primitive(bz[offset:], "int64")
    offset += n
    value, _ = decode_bytes(bz[offset:])
    print(f"updated at: {version}, value: {HexBytes(value).hex()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s", multiple=True)
def version(db, store):
    """
    print latest versions of iavl stores
    """
    if not store:
        raise click.UsageError("no store names are provided")
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        print(f"{s}: {latest_version(db, s)}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s", multiple=True)
def metadata(db, store):
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        bz = db.get(store_prefix(s) + b"m" + b"storage_version")
        print(f"{s} storage version: {bz.decode()}")


if __name__ == "__main__":
    cli()
