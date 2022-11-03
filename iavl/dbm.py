try:
    from . import rocksdb as dbm
except ImportError:
    try:
        from . import leveldb as dbm
    except ImportError:
        raise ImportError("no db backend supported")


open = dbm.open
WriteBatch = dbm.WriteBatch


class DBM:
    pass
