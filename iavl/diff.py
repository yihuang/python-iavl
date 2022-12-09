"""
tree diff algorithm between two versions
"""
import binascii
import itertools
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, List, NamedTuple, Optional, Tuple

from cprotobuf import Field, ProtoEntity, decode_primitive, encode_primitive

from .iavl import PersistedNode, Tree

GetNode = Callable[bytes, Optional[PersistedNode]]


class Op(IntEnum):
    Update, Delete, Insert = range(3)


Change = Tuple[bytes, Op, object]
ChangeSet = List[Change]


@dataclass
class Layer:
    """
    Represent one layer of nodes at the same height

    pending_nodes: because one of the children's height could be height-2, need to keep
    it in the pending list temporarily.
    """

    height: int = 0
    nodes: List[PersistedNode] = field(default_factory=list)
    pending_nodes: List[PersistedNode] = field(default_factory=list)

    @classmethod
    def root(cls, root):
        return cls(
            height=root.height,
            nodes=[root],
        )

    @classmethod
    def empty(cls, height):
        return cls(height=height)

    def next_layer(self, get_node: GetNode, predecessor):
        """
        travel to next layer
        """
        assert self.height > 0
        nodes = []
        pending_nodes = []
        for node in self.nodes:
            left = get_node(node.left_node_ref)
            if left.version > predecessor:
                if left.height == self.height - 1:
                    nodes.append(left)
                else:
                    pending_nodes.append(left)

            right = get_node(node.right_node_ref)
            if right.version > predecessor:
                if right.height == self.height - 1:
                    nodes.append(right)
                else:
                    pending_nodes.append(right)

        self.height -= 1

        # merge sorted lists
        self.nodes = nodes
        self.nodes += self.pending_nodes
        self.nodes.sort(key=lambda n: n.key)
        self.pending_nodes = pending_nodes

    def is_empty(self):
        return not self.nodes and not self.pending_nodes


def diff_sorted(nodes1, nodes2):
    """
    Contract: input list is sorted by node.key
    return: (common, orphaned, new)
    """
    i1 = i2 = 0
    common = []
    orphaned = []
    new = []
    while True:
        if i1 > len(nodes1) - 1:
            new += nodes2[i2:]
            break
        if i2 > len(nodes2) - 1:
            orphaned += nodes1[i1:]
            break
        k1 = nodes1[i1].key
        k2 = nodes2[i2].key
        if nodes1[i1].hash == nodes2[i2].hash:
            common.append(nodes1[i1])
            i1 += 1
            i2 += 1
        elif k1 == k2:
            # overriden by same key
            orphaned.append(nodes1[i1])
            new.append(nodes2[i2])
            i1 += 1
            i2 += 1
        elif k1 < k2:
            # proceed to next node in nodes1 until catch up with nodes2
            orphaned.append(nodes1[i1])
            i1 += 1
        else:
            # proceed to next node in nodes2 until catch up with nodes1
            new.append(nodes2[i2])
            i2 += 1
    return common, orphaned, new


class DiffOptions(NamedTuple):
    # predecessor will skip the subtrees at or before the predecessor from both trees.
    predecessor: int
    # in prune mode, the diff process stop as soon as orphaned nodes becomes empty.
    prune_mode: bool

    @classmethod
    def full(cls):
        "do a full diff, can be used for extracting state changes"
        return cls(predecessor=0, prune_mode=False)

    @classmethod
    def for_pruning(cls, predecessor: int):
        "do an optimized diff for pruning versions"
        return cls(predecessor=predecessor, prune_mode=True)


def diff_tree(
    get_node: GetNode, root1: PersistedNode, root2: PersistedNode, opts: DiffOptions
):
    """
    diff two versions of the iavl tree.
    yields (orphaned, new)

    predecessor can help to skip more subtrees when finding orphaned nodes, we don't
    need to traverse the subtrees that's created at or before predecessor in that case.
    """

    # skipping nodes created at or before predecessor
    if root1 is not None and root1.version <= opts.predecessor:
        root1 = None
    if root2 is not None and root2.version <= opts.predecessor:
        root2 = None

    # nothing to do if both tree are empty
    if root1 is None and root2 is None:
        return

    # if one is empty, create an empty layer with the same height as the other tree.
    if root1 is None:
        l1 = Layer.empty(root2.height)
        l2 = Layer.root(root2)
    elif root2 is None:
        l1 = Layer.root(root1)
        l2 = Layer.empty(root1.height)
    else:
        l1 = Layer.root(root1)
        l2 = Layer.root(root2)

    while l1.height > l2.height:
        yield l1.nodes, []
        l1.next_layer(get_node, opts.predecessor)

    while l2.height > l1.height:
        yield [], l2.nodes
        l2.next_layer(get_node, opts.predecessor)

    while True:
        # l1 l2 at the same height now
        _, orphaned, new = diff_sorted(l1.nodes, l2.nodes)

        yield orphaned, new

        if l1.height == 0:
            break

        # don't visit the common sub-trees
        l1.nodes = orphaned
        l2.nodes = new

        if opts.prune_mode and l1.is_empty():
            # nothing else to see in tree1, no more orphaned nodes, only new ones,
            # that's enough for pruning mode.
            break

        l1.next_layer(get_node, opts.predecessor)
        l2.next_layer(get_node, opts.predecessor)


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


def state_changes(get_node: GetNode, root1: PersistedNode, root2: PersistedNode):
    """
    extract state changes from the tree diff result

    return: [(key, op, arg)]
    arg: original value if op==Delete
         new value if op==Insert
         (original value, new value) if op==Update
    """
    for orphaned, new in diff_tree(get_node, root1, root2, DiffOptions.full()):
        # the nodes are on the same height, and we only care about leaf nodes here
        try:
            node = next(itertools.chain(orphaned, new))
        except StopIteration:
            continue

        if node.height == 0:
            return split_operations(orphaned, new)
    return []


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
