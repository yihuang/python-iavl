from iavl.iavl import NodeDB, Tree


def test_basic():
    db = NodeDB()
    tree = Tree(db, 0)
    assert not tree.set(b"hello", b"world")
    tree.save_version()

    tree = Tree(db, 1)
    assert b"world" == tree.get(b"hello")
    assert tree.set(b"hello", b"world1")
    assert not tree.set(b"hello1", b"world1")
    tree.save_version()

    tree = Tree(db, 2)
    assert b"world1" == tree.get(b"hello")
    assert b"world1" == tree.get(b"hello1")
    tree.set(b"hello2", b"world1")
    tree.set(b"hello3", b"world1")
    tree.save_version()

    tree = Tree(db, 3)
    assert b"world1" == tree.get(b"hello3")

    node = db.get(db.get_root_hash(3))
    assert 2 == node.height
