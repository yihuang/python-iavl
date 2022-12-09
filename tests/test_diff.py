from typing import NamedTuple

import rocksdb
from iavl.diff import DiffOptions, diff_sorted, diff_tree, state_changes
from iavl.iavl import NodeDB, Tree


def diff_tree_collect(ndb: NodeDB, v1: int, v2: int, opts: DiffOptions):
    orphaned = []
    new = []

    for o, n in diff_tree(ndb.get, ndb.get_root_node(v1), ndb.get_root_node(v2), opts):
        orphaned += o
        new += n

    return orphaned, new


def test_diff_sorted():
    class MockNode(NamedTuple):
        key: int
        hash: int

    def m(*xs):
        return [MockNode(x, x) for x in xs]

    assert (m(3, 4), m(1, 2), m(5, 6)) == diff_sorted(m(1, 2, 3, 4), m(3, 4, 5, 6))
    assert (m(3, 4), m(1, 2, 7, 8), m(5, 6)) == diff_sorted(
        m(1, 2, 3, 4, 7, 8), m(3, 4, 5, 6)
    )


def test_diff_tree(tmp_path):
    dbpath = tmp_path / "basic_ops"
    dbpath.mkdir()
    print("db", dbpath)
    kvdb = rocksdb.DB(str(dbpath), rocksdb.Options(create_if_missing=True))
    db = NodeDB(kvdb)

    tree = Tree(db, 0)
    assert not tree.set(b"hello", b"world")
    tree.save_version()

    tree = Tree(db, 1)
    assert tree.set(b"hello", b"world1")
    assert not tree.set(b"hello1", b"world1")
    tree.save_version()

    orphaned, new = diff_tree_collect(db, 1, 2, DiffOptions.full())
    assert len(orphaned) == 1
    assert len(new) == 3


def test_state_changes(tmp_path):
    from .test_iavl import ChangeSets, setup_test_tree

    dbpath = tmp_path / "prune"
    dbpath.mkdir()
    print("db", dbpath)
    kvdb = rocksdb.DB(str(dbpath), rocksdb.Options(create_if_missing=True))
    setup_test_tree(kvdb)

    db = NodeDB(kvdb)
    for i, changes in enumerate(ChangeSets):
        assert changes == state_changes(
            db.get, db.get_root_node(i), db.get_root_node(i + 1)
        )
