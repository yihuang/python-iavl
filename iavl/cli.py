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
    print root hashes of iavl stores
    """
    if not store:
        raise click.UsageError("no store names are provided")
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        if version is None:
            version = iavl_latest_version(db, s)
        bz = db.get(store_prefix(s) + root_key(version))
        print(f"{s}: {binascii.hexlify(bz).decode()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.argument("hash")
def node(db, hash, store):
    """
    print the content of a node
    """
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
    """
    print the content of a fast node
    """
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
def latest_version(db, store):
    """
    print latest versions of iavl stores
    """
    if not store:
        raise click.UsageError("no store names are provided")
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        print(f"{s}: {iavl_latest_version(db, s)}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s", multiple=True)
def metadata(db, store):
    """
    print storage version of iavl stores
    """
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    for s in store:
        bz = db.get(store_prefix(s) + b"m" + b"storage_version")
        print(f"{s} storage version: {bz.decode()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
def commit_infos(db):
    """
    print latest version and commit infos of rootmulti store
    """
    db = rocksdb.DB(str(db), rocksdb.Options(), read_only=True)
    bz = db.get(b"s/latest")
    version, _ = cprotobuf.decode_primitive(bz[1:], "uint64")
    print(f"latest version: {version}")
    bz = db.get(f"s/{version}".encode())
    res = CommitInfo()
    res.ParseFromString(bz)
    print(f"commit info version: {res.version}")
    for info in res.store_infos:
        print(
            f"store name: {info.name}, version: {info.commit_id.version}, hash: "
            f"{HexBytes(info.commit_id.hash).hex()}"
        )


if __name__ == "__main__":
    cli()
