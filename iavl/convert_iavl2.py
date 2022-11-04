"""
https://github.com/cosmos/iavl/pull/608

Experiment with the logic converting iavl tree to new node key,
to see how much disk space can be saved.
"""

import lmdb
import snappy
from hexbytes import HexBytes

from . import dbm
from .utils import (Node, Node2, decode_node, iavl_latest_version, node_key,
                    root_key, store_prefix, visit_iavl_nodes)


def convert_to_lmdb(db: dbm.DBM, store: str):
    prefix = store_prefix(store)
    version = iavl_latest_version(db, store)

    def get_node(hash: bytes) -> Node:
        n, _ = decode_node(db.get(prefix + node_key(hash)))
        return n

    size = 0
    compressed_size = 0
    node_map = {}  # map from node hash to (version, nonce)
    for v in range(0, version + 1):

        def prune_check(node: Node) -> (bool, bool):
            if node.version < v:
                # no need to visit children if parent node is old
                return True, True
            return False, False

        print("versin", v)
        nonce = 0
        root_hash = db.get(store_prefix(store) + root_key(v))
        if not root_hash:
            continue
        for hash, node in visit_iavl_nodes(
            get_node, prune_check, root_hash, preorder=False
        ):
            assert node.version <= v, f"{node.version} > {v}"
            if node.version != v:
                continue

            node2 = Node2.from_legacy_node(hash, node, node_map)
            bz = node2.encode()
            size += len(bz)
            compressed_size += len(snappy.compress(bz))

            key = (v, nonce)
            nonce += 1
            node_map[hash] = key

    print(size, compressed_size)


if __name__ == "__main__":
    import sys

    db1 = dbm.open(sys.argv[1], read_only=True)
    # db2 = lmdb.open(sys.argv[2], max_dbs=1024)
    store = sys.argv[2]
    convert_to_lmdb(db1, store)
