import rocksdb
from iavl.iavl import NodeDB
from iavl.utils import iter_iavl_tree


def test_prune_tree(tmp_path):
    from .test_iavl import EXPECT_OUTPUT, setup_test_tree

    dbpath = tmp_path / "prune"
    dbpath.mkdir()
    print("db", dbpath)
    kvdb = rocksdb.DB(str(dbpath), rocksdb.Options(create_if_missing=True))
    setup_test_tree(kvdb)

    db = NodeDB(kvdb)
    latest_version = db.latest_version()
    for i in range(1, latest_version):
        print("delete version", i)
        assert EXPECT_OUTPUT[i + 1].orphaned == db.delete_version(i)
        # check the integrity of the other versions
        for j in range(i + 1, latest_version):
            for _ in iter_iavl_tree(kvdb, None, db.get_root_hash(j), None, None):
                pass
