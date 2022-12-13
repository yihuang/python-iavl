"""
tree diff algorithm between two versions
"""
import binascii
from typing import List, NamedTuple

from cprotobuf import (Field, ProtoEntity, decode_primitive, encode_data,
                       encode_primitive)

from .iavl import PersistedNode, Tree
from .utils import GetNode, visit_iavl_nodes

VERSIONDB_MAGIC = b"VERDB000"


class KVPair(NamedTuple):
    delete: bool = False
    key: bytes = None
    value: bytes = None

    def as_json(self):
        d = {"key": binascii.hexlify(self.key).decode()}
        if self.value:
            d["value"] = binascii.hexlify(self.value).decode()
        if self.delete:
            d["delete"] = True
        return d


class StoreKVPair(ProtoEntity):
    delete = Field("bool", 1)
    key = Field("bytes", 2)
    value = Field("bytes", 3)

    def to_pair(self):
        return KVPair(self.delete, self.key, self.value)


ChangeSet = List[KVPair]


def state_changes(get_node: GetNode, version, root, successor_root) -> ChangeSet:
    """
    extract state changes from two versions of the iavl tree.

    first traverse the successor version to find the shared sub-root nodes
    and new leaf nodes, then traverse the target version to find the orphaned leaf
    nodes, then extract kv pair operations from it.

    return: [KVPair]
    """

    shared = set()
    new = []  # update and inserts
    new_keys = set()
    if successor_root:

        def successor_prune(n: PersistedNode) -> (bool, bool):
            b = n.version <= version
            return b, b

        for n in visit_iavl_nodes(get_node, successor_prune, successor_root):
            if n.version <= version:
                shared.add(n.hash)
            elif n.is_leaf():
                new.append(KVPair(key=n.key, value=n.value))
                new_keys.add(n.key)

    def prune(n: PersistedNode) -> (bool, bool):
        b = n.hash in shared
        return b, b

    if root:
        deleted = [
            KVPair(delete=True, key=n.key)
            for n in visit_iavl_nodes(get_node, prune, root)
            if n.is_leaf() and n.hash not in shared and n.key not in new_keys
        ]
    else:
        deleted = []

    changeset = new + deleted
    changeset.sort(key=lambda n: n.key)
    return changeset


def apply_change_set(tree: Tree, changeset: ChangeSet):
    """
    changeset: the result of `state_changes`
    """
    for pair in changeset:
        if pair.delete:
            tree.remove(pair.key)
        else:
            tree.set(pair.key, pair.value)


def append_change_set(fp, version: int, changeset: ChangeSet):
    """
    write change set to file, file format:

    ```
    version: varint
    size: varint little-endian # the total size of kv-pairs, so we can skip faster
    kv-pairs: length prefixed proto msg
    ```
    """
    chunks = []
    for kv in changeset:
        item = encode_data(StoreKVPair, kv._asdict())
        chunks.append(encode_primitive("uint64", len(item)))
        chunks.append(item)
    data = b"".join(chunks)
    fp.write(encode_primitive("uint64", version))
    fp.write(encode_primitive("uint64", len(data)))
    fp.write(data)


def parse_change_set(data, parse_body=True):
    """
    data is the bytes slice of a change set file,
    could be mmapped from the disk file.

    yield (version, [KVPair])
    """
    assert data[:8] == VERSIONDB_MAGIC
    offset = 8

    while offset < len(data):
        version, n = decode_primitive(data[offset:], "uint64")
        offset += n
        size, n = decode_primitive(data[offset:], "uint64")
        offset += n

        if not parse_body:
            yield version, None
            continue

        body = []
        limit = offset + size
        while offset < limit:
            l, n = decode_primitive(data[offset:], "uint64")
            offset += n

            pair = StoreKVPair()
            pair.ParseFromString(data[offset : offset + l])
            body.append(pair.to_pair())

            offset += l
        assert offset == limit, "corrupted file"
        yield version, body
