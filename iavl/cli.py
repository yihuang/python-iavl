import binascii
from typing import List, Optional

import click
import rocksdb


def root_key(v: int) -> bytes:
    return b"r" + v.to_bytes(8, "big")


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


if __name__ == "__main__":
    cli()
