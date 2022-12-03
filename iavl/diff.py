"""
tree diff algorithm between two versions
"""
import itertools
from enum import IntEnum
from typing import Callable, List, Optional, Tuple

from .iavl import PersistedNode, Tree

GetNode = Callable[bytes, Optional[PersistedNode]]


class Layer:
    """
    Represent one layer of nodes at the same height

    pending_nodes: because one of the children's height could be height-2, need to keep
    it in the pending list temporarily.
    """

    def __init__(self, nodes, pending_nodes):
        """
        Contract:
        - nodes are not empty
        - pending_nodes are at one layer below nodes
        """
        self.height = nodes[0].height if nodes else None
        self.nodes = nodes
        self.pending_nodes = pending_nodes

    @classmethod
    def root(cls, root):
        return cls([root] if root is not None else [], [])

    def next_layer(self, get_node: GetNode):
        """
        travel to next layer
        """
        assert self.height > 0
        nodes = []
        pending_nodes = []
        for node in self.nodes:
            left = get_node(node.left_node_ref)
            if left.height == self.height - 1:
                nodes.append(left)
            else:
                pending_nodes.append(left)

            right = get_node(node.right_node_ref)
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


def diff_tree(get_node: GetNode, root1: PersistedNode, root2: PersistedNode):
    """
    diff two versions of the iavl tree.
    yields (orphaned, new)
    """
    l1 = Layer.root(root1)
    l2 = Layer.root(root2)

    if l1.height is None:
        l1.height = l2.height

    if l1.height is None:
        # both trees are empty
        return [], []

    while l1.height > l2.height:
        yield l1.nodes, []
        l1.next_layer(get_node)

    while l2.height > l1.height:
        yield [], l2.nodes
        l2.next_layer(get_node)

    while True:
        # l1 l2 at the same height now
        _, orphaned, new = diff_sorted(l1.nodes, l2.nodes)

        yield orphaned, new

        if l1.height == 0:
            break

        # don't visit the common sub-trees
        l1.nodes = orphaned
        l2.nodes = new

        l1.next_layer(get_node)
        l2.next_layer(get_node)


class Op(IntEnum):
    Update, Delete, Insert = range(3)


def split_operations(nodes1, nodes2) -> List[Tuple[bytes, Op, object]]:
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
    for orphaned, new in diff_tree(get_node, root1, root2):
        # the nodes are on the same height, and we only care about leaf nodes here
        try:
            node = next(itertools.chain(orphaned, new))
        except StopIteration:
            continue

        if node.height == 0:
            return split_operations(orphaned, new)
    return []


def apply_change_set(tree: Tree, changeset):
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
