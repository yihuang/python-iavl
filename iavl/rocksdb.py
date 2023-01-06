import rocksdb


class WriteBatch:
    db: rocksdb.DB
    batch: rocksdb.WriteBatch

    def __init__(self, db):
        self.db = db
        self.batch = rocksdb.WriteBatch()

    def put(self, key: bytes, value: bytes):
        return self.batch.put(key, value)

    def delete(self, key: bytes):
        return self.batch.delete(key)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.db.write(self.batch)
        else:
            self.batch.close()


def open(dir, read_only: bool = False):
    opts = rocksdb.Options()
    if not read_only:
        opts.create_if_missing = True
    return rocksdb.DB(str(dir), opts, read_only=read_only)
