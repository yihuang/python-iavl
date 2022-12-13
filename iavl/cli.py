import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from hexbytes import HexBytes

from . import dbm, diff
from .iavl import NodeDB, Tree, delete_version
from .utils import (decode_fast_node, diff_iterators, encode_stdint,
                    fast_node_key, get_node, get_root_node,
                    iavl_latest_version, iter_fast_nodes, iter_iavl_tree,
                    load_commit_infos, root_key, store_prefix)
from .visualize import visualize_iavl, visualize_pruned_nodes


@click.group
def cli():
    pass


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
    db = dbm.open(str(db), read_only=True)
    if not store:
        # discover iavl store names from recent commit info
        res = load_commit_infos(db)
        store = [info.name for info in res.store_infos if info.commit_id.version > 0]
    for s in store:
        if version is None:
            version = iavl_latest_version(db, s)
        bz = db.get(store_prefix(s) + root_key(version))
        print(f"{s}: {binascii.hexlify(bz or b'').decode()}")


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option(
    "--version",
    help="the version to query, default to latest version if not provided",
    type=click.INT,
)
@click.option("--store", "-s", multiple=True)
def root_node(db, store: List[str], version: Optional[int]):
    """
    print root nodes of iavl stores
    """
    db = dbm.open(str(db), read_only=True)
    if not store:
        # discover iavl store names from recent commit info
        res = load_commit_infos(db)
        store = [info.name for info in res.store_infos if info.commit_id.version > 0]
    for s in store:
        if version is None:
            version = iavl_latest_version(db, s)
        node = get_root_node(db, version, s)
        if not node:
            print(f"{s}:")
            continue
        print(f"{s}: {json.dumps(node.as_json())}")


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option("--store", "-s")
@click.argument("hash")
def node(db, hash, store):
    """
    print the content of a node
    """
    db = dbm.open(str(db), read_only=True)
    node = get_node(db, HexBytes(hash), store)
    if not node:
        raise click.BadParameter("node for the hash don't exist")
    print(json.dumps(node.as_json()))


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
    if not bz:
        raise click.BadParameter("fast node for the key don't exist")
    version, value, _ = decode_fast_node(bz)
    print(f"updated at: {version}, value: {HexBytes(value).hex()}")


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
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
    A quick and dirty way to rollback chain state,
    may leave some orphan nodes in db, not a big deal.

    1. Delete the root nodes of iavl tree
    2. Delete related orphan entries
    3. Update latest version of multistore
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

            print("delete orphan entries created since target version")
            orphan_prefix = prefix + b"o" + target.to_bytes(8, "big")
            it = db.iterkeys()
            it.seek(orphan_prefix)
            for k in it:
                if not k.startswith(orphan_prefix):
                    break
                batch.delete(k)

            for v in range(ver, target, -1):
                print(f"delete root node, version: {v}, store: {info.name}")
                batch.delete(prefix + root_key(v))
        batch.put(b"s/latest", encode_stdint(target))
        print(f"update latest version to {target}")


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option(
    "--version",
    help="the version to query, default to latest version if not provided",
    type=click.INT,
)
@click.option(
    "--include-prev-version",
    help="include the previous version to compare",
    is_flag=True,
    default=False,
)
@click.option("--store", "-s")
def visualize(db, version, store=None, include_prev_version=False):
    """
    visualize iavl tree with dot, example:
    $ iavl-cli visualize --version 9 --db db --store bank | dot -Tpdf > /tmp/tree.pdf
    """
    db = dbm.open(str(db), read_only=True)
    if version is None:
        version = iavl_latest_version(db, store)

    prefix = store_prefix(store) if store is not None else b""
    root_hash = db.get(prefix + root_key(version))
    root_hash2 = None
    if include_prev_version and version > 1:
        root_hash2 = db.get(prefix + root_key(version - 1))
    g = visualize_iavl(db, prefix, root_hash, version, root_hash2=root_hash2)
    print(g.source)


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option("--store", "-s")
@click.option(
    "--start-version",
    help="the version to start, default to 1",
    default=1,
    type=click.INT,
)
@click.option(
    "--end-version",
    help="the end version, default to latest version",
    type=click.INT,
)
@click.option(
    "--out-dir",
    help="the output directory to save the data files",
    type=click.Path(exists=True),
    required=True,
)
def dump_changesets(db, start_version, end_version, store: Optional[str], out_dir: str):
    """
    extract changeset by comparing iavl versions and save in files
    with compatible format with file streamer.
    end_version is exclusive.
    """
    db = dbm.open(str(db), read_only=True)
    prefix = store_prefix(store) if store is not None else b""
    ndb = NodeDB(db, prefix=prefix)
    with (Path(out_dir) / f"block-{start_version}").open("wb") as fp:
        fp.write(diff.VERSIONDB_MAGIC)
        for _, v, _, changeset in iter_state_changes(
            db, ndb, start_version=start_version, end_version=end_version, prefix=prefix
        ):
            diff.append_change_set(fp, v, changeset)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--parse-kv-pairs/--no-parse-kv-pairs",
    default=True,
    help="if parse the changeset kv pairs",
)
def print_changeset(file, parse_kv_pairs):
    """
    decode and print the content of changeset files
    """
    for version, items in diff.parse_change_set(
        Path(file).read_bytes(), parse_kv_pairs
    ):
        print("version:", version)
        if items is None:
            continue
        for item in items:
            print(json.dumps(item.as_json()))


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option("--store", "-s")
@click.option(
    "--start-version",
    help="the version to start check",
    default=1,
)
def test_state_round_trip(db, store, start_version):
    """
    extract state changes from iavl versions,
    reapply and check if we can get back the same root hash
    """
    db = dbm.open(str(db), read_only=True)
    prefix = store_prefix(store) if store is not None else b""
    ndb = NodeDB(db, prefix=prefix)
    for pversion, v, root, changeset in iter_state_changes(
        db, ndb, start_version=start_version, prefix=prefix
    ):
        # re-apply changeset
        tree = Tree(ndb, pversion)
        diff.apply_change_set(tree, changeset)
        tmp = tree.save_version(dry_run=True)
        if (root or hashlib.sha256().digest()) == tmp:
            print(v, len(changeset), "ok")
        else:
            print(
                v,
                len(changeset),
                "fail",
                binascii.hexlify(root).decode(),
                binascii.hexlify(tmp).decode(),
            )


def iter_state_changes(
    db: dbm.DBM, ndb: NodeDB, start_version=0, end_version=None, prefix=b""
):
    pversion = ndb.prev_version(start_version) or 0
    prev_root = ndb.get_root_hash(pversion)
    it = db.iteritems()
    it.seek(prefix + root_key(start_version))
    for k, hash in it:
        if not k.startswith(prefix + b"r"):
            break
        v = int.from_bytes(k[len(prefix) + 1 :], "big")
        if end_version is not None and v >= end_version:
            break

        yield pversion, v, hash, diff.state_changes(ndb.get, pversion, prev_root, hash)

        pversion = v
        prev_root = hash


@cli.command()
@click.option(
    "--db", help="path to application.db", type=click.Path(exists=True), required=True
)
@click.option("--store", "-s")
@click.option(
    "--version",
    help="the version to prune",
    default=1,
)
def visualize_pruning(db, store, version):
    """
    used to analyzsis performance of pruning algorithm on production data.
    """
    db = dbm.open(str(db), read_only=True)
    prefix = store_prefix(store) if store is not None else b""
    ndb = NodeDB(db, prefix=prefix)
    predecessor = ndb.prev_version(version) or 0
    successor = ndb.next_version(version)
    root1 = ndb.get_root_hash(version)
    root2 = ndb.get_root_hash(successor)

    touched_nodes = set()

    def trace_get(hash):
        touched_nodes.add(hash)
        return ndb.get(hash)

    deleted = set()
    for n in delete_version(
        trace_get,
        version,
        predecessor,
        root1,
        root2,
    ):
        deleted.add(n.hash)

    print(
        "delete version:",
        version,
        "predecessor:",
        predecessor,
        "successor:",
        successor,
        file=sys.stderr,
    )
    print(
        "delete:",
        len(deleted),
        "load:",
        len(touched_nodes),
        file=sys.stderr,
    )
    g = visualize_pruned_nodes(successor, touched_nodes, deleted, ndb)
    print(g.source)


if __name__ == "__main__":
    cli()
