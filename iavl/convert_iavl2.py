"""
https://github.com/cosmos/iavl/pull/608

Experiment with the logic converting iavl tree to new node key,
to see how much disk space can be saved.
"""

from . import dbm
from .utils import (Node, Node2, decode_node, iavl_latest_version, node_key,
                    root_key, store_prefix, visit_iavl_nodes)


def convert(db: dbm.DBM, db2: dbm.DBM, store: str):
    prefix = store_prefix(store)
    version = iavl_latest_version(db, store)

    def get_node(hash: bytes) -> Node:
        n, _ = decode_node(db.get(prefix + node_key(hash)))
        return n

    node_map = {}  # map from node hash to (version, nonce)
    for v in range(0, version + 1):

        def prune_check(node: Node) -> (bool, bool):
            if node.version < v:
                # no need to visit children if parent node is old
                return True, True
            return False, False

        print("version", v)
        root_hash = db.get(store_prefix(store) + root_key(v))
        if not root_hash:
            continue

        pending = []
        for hash, node in visit_iavl_nodes(get_node, prune_check, root_hash):
            assert node.version <= v, f"{node.version} > {v}"
            if node.version != v:
                continue

            node_map[hash] = (v, len(pending))
            pending.append((hash, node))

        with dbm.WriteBatch(db2) as batch:
            for nonce, (hash, node) in enumerate(pending):
                node2 = Node2.from_legacy_node(hash, node, node_map)
                batch.put(
                    v.to_bytes(8, "big") + nonce.to_bytes(4, "big"),
                    node2.encode(),
                )
