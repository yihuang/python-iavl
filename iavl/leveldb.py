import plyvel


class Iterator:
    def __init__(
        self, db, include_key: bool = True, include_value: bool = True, reversed=False
    ):
        self.db = db
        self.include_key = include_key
        self.include_value = include_value
        self.reversed = reversed

        self._it = db.iterator(
            include_key=include_key, include_value=include_value, reverse=reversed
        )

    def __reversed__(self):
        return Iterator(
            self.db, self.include_key, self.include_value, not self.reversed
        )

    def seek(self, key: bytes):
        self._it.seek(key)

    def __iter__(self):
        return self

    def __next__(self):
        return self._it.__next__()


class LevelDB:
    db: plyvel.DB

    def __init__(self, db):
        self.db = db

    def get(self, key: bytes):
        return self.db.get(key)

    def put(self, key: bytes, value: bytes):
        return self.db.put(key, value)

    def delete(self, key: bytes):
        return self.db.delete(key)

    def iterkeys(self):
        return Iterator(self.db, include_value=False)

    def iteritems(self):
        return Iterator(self.db)


def open(dir, read_only: bool = False, create_if_missing=False):
    return LevelDB(plyvel.DB(str(dir)), create_if_missing=create_if_missing)


def WriteBatch(db):
    return db.db.write_batch()
