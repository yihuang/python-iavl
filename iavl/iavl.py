"""
Support modify iavl tree
"""
import hashlib
from dataclasses import dataclass
from typing import Callable, NamedTuple, Optional, Union

import cprotobuf

import rocksdb

from .utils import Node as PersistedNode
from .utils import encode_bytes, node_key, root_key

NodeRef = Union[bytes, "Node"]


class NodeDB:
    """
    Load and cache persisted nodes
    """

    db: rocksdb.DB
    batch: rocksdb.WriteBatch

    def __init__(self, db):
        self.db = db
        self.batch = None

    def get(self, hash: bytes):
        return PersistedNode.decode(self.db.get(node_key(hash)))

    def resolve_node(self, ref: NodeRef) -> Union["Node", PersistedNode, None]:
        if isinstance(ref, Node):
            return ref
        elif ref is not None:
            return self.get(ref)

    def batch_set_node(self, hash: bytes, node: PersistedNode):
        if self.batch is None:
            self.batch = rocksdb.WriteBatch()
        self.batch.put(node_key(hash), node.encode())

    def batch_set_root_hash(self, version: int, hash: bytes):
        if self.batch is None:
            self.batch = rocksdb.WriteBatch()
        self.batch.put(root_key(version), hash)

    def batch_commit(self):
        if self.batch is not None:
            self.db.write(self.batch)
            self.batch = None

    def get_root_hash(self, version: int) -> Optional[bytes]:
        return self.db.get(root_key(version))


@dataclass
class Node:
    """
    Working node that's modified in memory
    """

    version: int  # the version created at
    key: bytes = None

    height: int = 0  # height of subtree
    size: int = 1  # size of subtree

    # only in leaf node
    value: Optional[bytes] = None

    # None: leaf node
    # bytes: hash of persisted node
    # Node: object of the working node
    left_node_ref: Union[None, bytes, "Node"] = None
    right_node_ref: Union[None, bytes, "Node"] = None

    @classmethod
    def new_leaf(cls, key: bytes, value: bytes, version: int):
        """
        create a working leaf node
        """
        return cls(key=key, value=value, version=version)

    @classmethod
    def from_branch_node(
        cls,
        node: Union["Node", PersistedNode],
        version: int,
        left_node_ref: Optional[NodeRef] = None,
        right_node_ref: Optional[NodeRef] = None,
    ):
        """
        clone a branch node and modify
        """
        res = cls(
            height=node.height,
            size=node.size,
            version=version,
            key=node.key,
            left_node_ref=node.left_node_ref,
            right_node_ref=node.right_node_ref,
        )

        # override
        if left_node_ref is not None:
            res.left_node_ref = left_node_ref
        if right_node_ref is not None:
            res.right_node_ref = right_node_ref
        return res

    def persisted(self) -> PersistedNode:
        return PersistedNode(
            height=self.height,
            size=self.size,
            version=self.version,
            key=self.key,
            value=self.value,
            left_node_ref=self.left_node_ref,
            right_node_ref=self.right_node_ref,
        )

    def is_leaf(self):
        return self.height == 0

    def left_node(self, ndb: NodeDB):
        return ndb.resolve_node(self.left_node_ref)

    def right_node(self, ndb: NodeDB):
        return ndb.resolve_node(self.right_node_ref)

    def hash(self):
        "compute hash of this node"
        chunks = [
            cprotobuf.encode_primitive("sint64", self.height),
            cprotobuf.encode_primitive("sint64", self.size),
            cprotobuf.encode_primitive("sint64", self.version),
        ]
        if self.is_leaf():
            chunks += encode_bytes(self.key) + encode_bytes(
                hashlib.sha256(self.value).digest()
            )
        else:
            chunks += encode_bytes(self.left_node_ref) + encode_bytes(
                self.right_node_ref
            )
        return hashlib.sha256(b"".join(chunks)).digest()

    def rotate_left(self, ndb: NodeDB, version: int) -> "Node":
        r"""
          S              R
         / \     =>     / \
             R         S
            / \       / \
          RL             RL
        """
        rnode = self.right_node(ndb)
        self.right_node_ref = rnode.left_node_ref
        new = Node.from_branch_node(rnode, version, left_node_ref=self)
        self.update_height_size(ndb)
        new.update_height_size(ndb)
        return new

    def rotate_right(self, ndb: NodeDB, version: int):
        r"""
           S               L
          / \      =>     / \
         L                   S
        / \                 / \
          LR               LR
        """
        lnode = self.left_node(ndb)
        self.left_node_ref = lnode.right_node_ref
        new = Node.from_branch_node(lnode, version, right_node_ref=self)
        self.update_height_size(ndb)
        new.update_height_size(ndb)
        return new

    def update_height_size(self, ndb: NodeDB):
        lnode = self.left_node(ndb)
        rnode = self.right_node(ndb)
        self.height = max(lnode.height, rnode.height) + 1
        self.size = lnode.size + rnode.size

    def balance(self, ndb: NodeDB, version: int):
        lnode = self.left_node(ndb)
        rnode = self.right_node(ndb)
        balance = lnode.height - rnode.height
        if balance > 1:
            lbalance = lnode.left_node(ndb).height - lnode.right_node(ndb).height
            if lbalance >= 0:
                # left left
                return self.rotate_right(ndb, version)
            else:
                # left right
                self.left_node_ref = lnode.rotate_left(ndb, version)
                return self.rotate_right(ndb, version)
        elif balance < -1:
            rbalance = rnode.left_node(ndb).height - rnode.right_node(ndb).height
            if rbalance < 0:
                # right right
                return self.rotate_left(ndb, version)
            else:
                # right left
                self.right_node_ref = rnode.rotate_right(ndb, version)
                return self.rotate_left(ndb, version)
        else:
            return self


class Tree:
    ndb: NodeDB
    root_node_ref: Union[None, bytes, Node]
    version: int

    def __init__(self, ndb: NodeDB, version: int):
        self.ndb = ndb
        self.version = version
        self.root_node_ref = ndb.get_root_hash(version)

    def root_node(self):
        return self.ndb.resolve_node(self.root_node_ref)

    def set(self, key: bytes, value: bytes):
        if self.root_node_ref is None:
            self.root_node_ref = Node.new_leaf(key, value, self.version + 1)
            return False
        self.root_node_ref, updated = set_recursive(
            self.ndb, self.root_node_ref, key, value, self.version + 1
        )
        return updated

    def get(self, key: bytes):
        if self.root_node_ref is None:
            return
        return get_recursive(self.ndb, key, self.root_node())

    def remove(self, key: bytes) -> Optional[bytes]:
        "remove the key and return the value, return None if not found."
        if self.root_node_ref is None:
            return
        value, self.root_node_ref = remove_recursive(
            self.ndb, key, self.root_node_ref, self.version + 1
        )
        return value

    def save_branch(
        self, node: Node, save_node: Callable[[bytes, Node], None]
    ) -> bytes:
        """
        traverse the working nodes to update hashes and save nodes
        """
        if isinstance(node.left_node_ref, Node):
            node.left_node_ref = self.save_branch(node.left_node_ref, save_node)
        if isinstance(node.right_node_ref, Node):
            node.right_node_ref = self.save_branch(node.right_node_ref, save_node)

        hash = node.hash()
        save_node(hash, node)
        return hash

    def save_version(self):
        def save_node(hash: bytes, node: Node):
            self.ndb.batch_set_node(hash, node.persisted())

        if isinstance(self.root_node_ref, Node):
            self.root_node_ref = self.save_branch(self.root_node_ref, save_node)
        self.version += 1
        root_hash = self.root_node_ref or hashlib.sha256().digest()
        self.ndb.batch_set_root_hash(self.version, root_hash)
        self.ndb.batch_commit()
        return root_hash


def remove_recursive(
    ndb: NodeDB,
    key: bytes,
    ref: NodeRef,
    version: int,
) -> (Optional[bytes], Optional[NodeRef]):
    """
    returns (removed value, new node if changed)
    - (None, _) -> nothing changed in subtree
    - (value, None) -> leaf node is removed
    - (value, new node) -> subtree changed
    """
    node = ndb.resolve_node(ref)
    if node.is_leaf():
        if node.key == key:
            return node.value, None
        else:
            return None, None
    else:
        turn_left = key < node.key
        if turn_left:
            value, new_child = remove_recursive(ndb, key, node.left_node_ref, version)
        else:
            value, new_child = remove_recursive(ndb, key, node.right_node_ref, version)

        if value is None:
            return

        if new_child is None:
            # return the other child
            if turn_left:
                return value, node.right_node_ref
            else:
                return value, node.left_node_ref
        else:
            # update the subtree
            if turn_left:
                new = Node.from_branch_node(node, version, left_node_ref=new_child)
            else:
                new = Node.from_branch_node(node, version, right_node_ref=new_child)
            new.update_height_size(ndb)
            return value, new.balance(ndb, version)


def set_recursive(
    ndb: NodeDB, ref: NodeRef, key: bytes, value: bytes, version: int
) -> (Node, bool):
    """
    return new node and if it update an existing key.
    """
    node = ndb.resolve_node(ref)
    if node.is_leaf():
        if key < node.key:
            return (
                Node(
                    version=version,
                    key=key,
                    height=1,
                    size=2,
                    left_node_ref=Node.new_leaf(key, value, version),
                    right_node_ref=ref,
                ),
                False,
            )
        elif key > node.key:
            return (
                Node(
                    version=version,
                    key=key,
                    height=1,
                    size=2,
                    left_node_ref=ref,
                    right_node_ref=Node.new_leaf(key, value, version),
                ),
                False,
            )
        else:
            return Node.new_leaf(key, value, version), True
    else:
        if key < node.key:
            lnode, updated = set_recursive(ndb, node.left_node_ref, key, value, version)
            new = Node.from_branch_node(
                node,
                version,
                left_node_ref=lnode,
            )
        else:
            rnode, updated = set_recursive(
                ndb, node.right_node_ref, key, value, version
            )
            new = Node.from_branch_node(
                node,
                version,
                right_node_ref=rnode,
            )

        if not updated:
            # tree shape is changed, re-balance
            new.update_height_size(ndb)
            new = new.balance(ndb, version)

        return new, updated


def get_recursive(
    ndb: NodeDB, key: bytes, node: Union[Node, PersistedNode]
) -> Optional[bytes]:
    if node.is_leaf():
        if node.key == key:
            return node.value
        else:
            return
    else:
        if key < node.key:
            return get_recursive(ndb, key, node.left_node(ndb))
        else:
            return get_recursive(ndb, key, node.right_node(ndb))
