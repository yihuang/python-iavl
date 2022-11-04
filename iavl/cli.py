import binascii
import json
from typing import List, Optional

import click
from hexbytes import HexBytes

from . import dbm
from .utils import (decode_fast_node, decode_node, diff_iterators,
                    encode_stdint, fast_node_key, iavl_latest_version,
                    iter_fast_nodes, iter_iavl_tree, load_commit_infos,
                    node_key, root_key, store_prefix)


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
    db = dbm.open(str(db), read_only=True)
    for s in store:
        if version is None:
            version = iavl_latest_version(db, s)
        bz = db.get(store_prefix(s) + root_key(version))
        print(f"{s}: {binascii.hexlify(bz or b'').decode()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.argument("hash")
def node(db, hash, store):
    """
    print the content of a node
    """
    db = dbm.open(str(db), read_only=True)
    bz = db.get(store_prefix(store) + node_key(HexBytes(hash)))
    node, _ = decode_node(bz)
    print(json.dumps(node.as_json()))


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
    db = dbm.open(str(db), read_only=True)
    bz = db.get(store_prefix(store) + fast_node_key(HexBytes(key)))
    version, value, _ = decode_fast_node(bz)
    print(f"updated at: {version}, value: {HexBytes(value).hex()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s", multiple=True)
def metadata(db, store):
    """
    print storage version and latest version of iavl stores
    """
    if not store:
        raise click.UsageError("no store names are provided")
    db = dbm.open(str(db), read_only=True)
    for s in store:
        bz = db.get(store_prefix(s) + b"m" + b"storage_version")
        print(f"{s} storage version: {bz.decode()}")
        print(f"{s} latest version: {iavl_latest_version(db, s)}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option(
    "--version",
    help="the version to query, default to latest version if not provided",
    type=click.INT,
)
def commit_infos(db, version):
    """
    print latest version and commit infos of rootmulti store
    """
    db = dbm.open(str(db), read_only=True)
    res = load_commit_infos(db, version)
    print(f"version: {res.version}")
    for info in res.store_infos:
        print(
            f"store name: {info.name}, version: {info.commit_id.version}, hash: "
            f"{HexBytes(info.commit_id.hash).hex()}"
        )


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.option(
    "--version",
    help="the version to query, default to latest version if not provided",
    type=click.INT,
)
@click.option("--start")
@click.option("--end")
@click.option("--output-value", is_flag=True, default=False)
def range_iavl(db, store, version, start, end, output_value):
    """
    iterate iavl tree
    """
    if not store:
        raise click.UsageError("no store names are provided")
    if start is not None:
        start = HexBytes(start)
    if end is not None:
        end = HexBytes(end)
    db = dbm.open(str(db), read_only=True)

    # find root node first
    if version is None:
        version = iavl_latest_version(db, store)
    root_hash = db.get(store_prefix(store) + root_key(version))
    for k, v in iter_iavl_tree(db, store, root_hash, start, end):
        if output_value:
            print(f"{HexBytes(k).hex()} {HexBytes(v).hex()}")
        else:
            print(HexBytes(k).hex())


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.option("--start")
@click.option("--end")
@click.option("--output-value", is_flag=True, default=False)
def range_fastnode(db, store, start, end, output_value):
    """
    iterate fast node index
    """
    if not store:
        raise click.UsageError("no store names are provided")
    if start is not None:
        start = HexBytes(start)
    if end is not None:
        end = HexBytes(end)
    db = dbm.open(str(db), read_only=True)
    for k, v in iter_fast_nodes(db, store, start, end):
        if output_value:
            print(f"{HexBytes(k).hex()} {HexBytes(v).hex()}")
        else:
            print(HexBytes(k).hex())


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option("--store", "-s")
@click.option("--start")
@click.option("--end")
@click.option("--output-value", is_flag=True, default=False)
def diff_fastnode(db, store, start, end, output_value):
    """
    compare fast node index with latest iavl tree version,
    to see if there are any differences.
    """
    if not store:
        raise click.UsageError("no store names are provided")
    if start is not None:
        start = HexBytes(start)
    if end is not None:
        end = HexBytes(end)
    db = dbm.open(str(db), read_only=True)
    it1 = iter_fast_nodes(db, store, start, end)

    # find root node first
    version = iavl_latest_version(db, store)
    root_hash = db.get(store_prefix(store) + root_key(version))
    it2 = iter_iavl_tree(db, store, root_hash, start, end)

    for status, k, v in diff_iterators(it1, it2):
        if status == 0:
            flag = "*"
        elif status == 1:
            flag = "-"
        else:
            flag = "+"
        if output_value:
            print(f"{flag} {HexBytes(k).hex()} {v}")
        else:
            print(f"{flag} {HexBytes(k).hex()}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option(
    "--target",
    help="rollback to target version, default to latest version minus 1",
    type=click.INT,
)
def fast_rollback(
    db,
    target: Optional[int],
):
    """
    A quick and dirty way to rollback chain state

    1. Delete the root nodes of iavl tree
    2. Update latest version of multistore
    """
    db = dbm.open(str(db))
    info = load_commit_infos(db)
    if target is None:
        target = info.version - 1
    assert target < info.version, f"can't rollback to {target}, latest {info.version}"

    print("rollback to", target)
    with dbm.WriteBatch(db) as batch:
        for info in info.store_infos:
            if info.commit_id.version == 0:
                # not iavl store
                continue

            prefix = store_prefix(info.name)
            ver = iavl_latest_version(db, info.name)
            for v in range(ver, target, -1):
                print(f"delete root node, version: {v}, store: {info.name}")
                batch.delete(prefix + root_key(v))
        batch.put(b"s/latest", encode_stdint(target))
        print(f"update latest version to {target}")


@cli.command()
@click.option("--db", help="path to application.db", type=click.Path(exists=True))
@click.option(
    "--target-db",
    help="path to target db, create if missing",
    type=click.Path(exists=True),
)
@click.option("--store", "-s")
def convert_iavl2(db, target_db, store):
    from .convert_iavl2 import convert

    db = dbm.open(db, read_only=True)
    db2 = dbm.open(target_db, create_if_missing=True)
    convert(db, db2, store)


if __name__ == "__main__":
    cli()
