"""
tree diff algorithm between two versions
"""
import binascii
from enum import IntEnum
from typing import List, Tuple

from cprotobuf import Field, ProtoEntity, decode_primitive, encode_primitive

from .iavl import PersistedNode, Tree
from .utils import GetNode, visit_iavl_nodes


class Op(IntEnum):
    Update, Delete, Insert = range(3)


Change = Tuple[bytes, Op, object]
ChangeSet = List[Change]


def split_operations(nodes1, nodes2) -> ChangeSet:
    """
    Contract: input nodes are all leaf nodes, sorted by node.key

    return: [(key, op, arg)]
    arg: original value if op==Delete
         new value if op==Insert
         (original value, new value) if op==Update
    """
    i1 = i2 = 0
    result = []
    while True:
        if i1 > len(nodes1) - 1:
            for n in nodes2[i2:]:
                result.append((n.key, Op.Insert, n.value))
            break
        if i2 > len(nodes2) - 1:
            for n in nodes1[i1:]:
                result.append((n.key, Op.Delete, n.value))
            break
        n1 = nodes1[i1]
        n2 = nodes2[i2]
        k1 = n1.key
        k2 = n2.key
        if k1 == k2:
            result.append((k1, Op.Update, (n1.value, n2.value)))
            i1 += 1
            i2 += 1
        elif k1 < k2:
            # proceed to next node in nodes1 until catch up with nodes2
            result.append((n1.key, Op.Delete, n1.value))
            i1 += 1
        else:
            # proceed to next node in nodes2 until catch up with nodes1
            result.append((n2.key, Op.Insert, n2.value))
            i2 += 1
    return result


def state_changes(get_node: GetNode, version, root, successor_root):
    """
    extract state changes from two versions of the iavl tree.

    first traverse the successor version to find the shared sub-root nodes
    and new leaf nodes, then traverse the target version to find the orphaned leaf
    nodes, then extract kv pair operations from it.

    return: [(key, op, arg)]
    arg: original value if op==Delete
         new value if op==Insert
         (original value, new value) if op==Update
    """

    shared = set()
    new = []
    if successor_root:

        def successor_prune(n: PersistedNode) -> (bool, bool):
            b = n.version <= version
            return b, b

        for n in visit_iavl_nodes(get_node, successor_prune, successor_root):
            if n.version <= version:
                shared.add(n.hash)
            elif n.is_leaf():
                new.append(n)

    def prune(n: PersistedNode) -> (bool, bool):
        b = n.hash in shared
        return b, b

    if root:
        orphaned = [
            n
            for n in visit_iavl_nodes(get_node, prune, root)
            if n.is_leaf() and n.hash not in shared
        ]
    else:
        orphaned = []

    return split_operations(orphaned, new)


def apply_change_set(tree: Tree, changeset: ChangeSet):
    """
    changeset: the result of `state_changes`
    """
    for key, op, arg in changeset:
        if op == Op.Insert:
            tree.set(key, arg)
        elif op == Op.Update:
            _, value = arg
            tree.set(key, value)
        elif op == Op.Delete:
            tree.remove(key)
        else:
            raise NotImplementedError(f"unknown op {op}")


class StoreKVPairs(ProtoEntity):
    """
    protobuf format compatible with file streamer output
    store an additional original value, it's empty for insert operation.
    """

    # the store key for the KVStore this pair originates from
    store_key = Field("string", 1)
    # true indicates a delete operation
    delete = Field("bool", 2)
    key = Field("bytes", 3)
    value = Field("bytes", 4)
    original = Field("bytes", 5)

    def as_json(self):
        d = {"key": binascii.hexlify(self.key).decode()}
        if self.store_key:
            d["store_key"] = self.store_key
        if self.value:
            d["value"] = binascii.hexlify(self.value).decode()
        if self.original:
            d["original"] = binascii.hexlify(self.original).decode()
        if self.delete:
            d["delete"] = True
        return d


def write_change_set(fp, changeset: ChangeSet, store=""):
    """
    write change set to file, compatible with the file streamer output.
    """
    chunks = []
    for key, op, arg in changeset:
        kv = StoreKVPairs(store_key=store, key=key)
        if op == Op.Delete:
            kv.delete = True
            kv.original = arg
        elif op == Op.Update:
            kv.original, kv.value = arg
        elif op == Op.Insert:
            kv.value = arg
        item = kv.SerializeToString()
        chunks.append(encode_primitive("uint64", len(item)))
        chunks.append(item)
    data = b"".join(chunks)
    fp.write(len(data).to_bytes(8, "big"))
    fp.write(data)


def parse_change_set(data):
    """
    return list of StoreKVPairs
    """
    size = int.from_bytes(data[:8], "big")
    assert len(data) == size + 8
    offset = 8
    items = []
    while offset < len(data):
        size, n = decode_primitive(data[offset:], "uint64")
        offset += n
        item = StoreKVPairs()
        item.ParseFromString(data[offset : offset + size])
        items.append(item)
        offset += size
    return items
