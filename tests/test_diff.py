import rocksdb
from iavl.diff import state_changes
from iavl.iavl import NodeDB


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
            db.get, i, db.get_root_hash(i), db.get_root_hash(i + 1)
        )
