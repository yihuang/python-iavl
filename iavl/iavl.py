"""
Support modify iavl tree
"""
import binascii
import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, NamedTuple, Optional, Union

import cprotobuf

from .utils import encode_bytes

NodeRef = Union[bytes, "Node"]


class PersistedNode(NamedTuple):
    """
    immutable nodes that's loaded from and save to db
    """

    height: int  # height of subtree
    size: int  # size of subtree
    version: int  # the version created at
    key: bytes

    # only in leaf node
    value: Optional[bytes]

    # only in branch nodes
    left_node_ref: Optional[bytes]
    right_node_ref: Optional[bytes]

    def is_leaf(self):
        return self.height == 0

    def left_node(self, ndb: "NodeDB"):
        if self.left_node_ref is not None:
            return ndb.get(self.left_node_ref)

    def right_node(self, ndb: "NodeDB"):
        if self.right_node_ref is not None:
            return ndb.get(self.right_node_ref)


class NodeDB:
    """
    Load and cache persisted nodes
    """

    store: Dict[bytes, PersistedNode]
    versions: Dict[int, bytes]

    def __init__(self):
        self.store = {}
        self.versions = {}

    def get(self, hash: bytes):
        return self.store.get(hash)

    def resolve_node(self, ref: NodeRef) -> Union["Node", PersistedNode, None]:
        if isinstance(ref, Node):
            return ref
        elif ref is not None:
            return self.get(ref)

    def set(self, hash: bytes, node: PersistedNode):
        self.store[hash] = node

    def set_root_hash(self, version: int, hash: bytes):
        self.versions[version] = hash

    def get_root_hash(self, version: int):
        return self.versions.get(version)


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
        left_node: Optional["Node"] = None,
        right_node: Optional["Node"] = None,
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
        if left_node is not None:
            res.left_node_ref = left_node
        if right_node is not None:
            res.right_node_ref = right_node
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

    def update_height_size(self, ndb: NodeDB):
        lnode = self.left_node(ndb)
        rnode = self.right_node(ndb)
        self.height = max(lnode.height, rnode.height) + 1
        self.size = lnode.size + rnode.size

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
        new = Node.from_branch_node(rnode, version, left_node=self)
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
        new = Node.from_branch_node(lnode, version, right_node=self)
        self.update_height_size(ndb)
        new.update_height_size(ndb)
        return new


class Tree:
    ndb: NodeDB
    versions: Dict[int, bytes]
    root_node_ref: Union[None, bytes, Node]
    version: int

    def __init__(self, ndb: NodeDB, version: int):
        self.ndb = ndb
        self.version = version
        self.root_node_ref = ndb.get_root_hash(version)

    def root_node(self):
        if isinstance(self.root_node_ref, Node):
            return self.root_node_ref
        elif self.root_node_ref is not None:
            return self.ndb.get(self.root_node_ref)

    def set(self, key: bytes, value: bytes):
        if self.root_node_ref is None:
            self.root_node_ref = Node.new_leaf(key, value, self.version + 1)
            return False
        self.root_node_ref, updated = self.set_recursive(
            self.root_node_ref, key, value, self.version + 1
        )
        return updated

    def set_recursive(
        self, ref: NodeRef, key: bytes, value: bytes, version: int
    ) -> (Node, bool):
        """
        return new node and if it update an existing key.
        """
        node = self.ndb.resolve_node(ref)
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
                lnode, updated = self.set_recursive(
                    node.left_node_ref, key, value, version
                )
                new = Node.from_branch_node(
                    node,
                    version,
                    left_node=lnode,
                )
            else:
                rnode, updated = self.set_recursive(
                    node.right_node_ref, key, value, version
                )
                new = Node.from_branch_node(
                    node,
                    version,
                    right_node=rnode,
                )

            if not updated:
                # tree shape is changed, re-balance
                new.update_height_size(self.ndb)
                new = self.balance(new, version)

            return new, updated

    def get(self, key: bytes):
        if self.root_node_ref is None:
            return
        return self.get_recursive(key, self.root_node())

    def get_recursive(
        self, key: bytes, node: Union[Node, PersistedNode]
    ) -> Optional[bytes]:
        if node.is_leaf():
            if node.key == key:
                return node.value
            else:
                return
        else:
            if key < node.key:
                return self.get_recursive(key, node.left_node(self.ndb))
            else:
                return self.get_recursive(key, node.right_node(self.ndb))

    def balance(self, node: Node, version: int):
        lnode = node.left_node(self.ndb)
        rnode = node.right_node(self.ndb)
        balance = lnode.height - rnode.height
        if balance > 1:
            lbalance = (
                lnode.left_node(self.ndb).height - lnode.right_node(self.ndb).height
            )
            if lbalance >= 0:
                # left left
                return node.rotate_right(self.ndb, version)
            else:
                # left right
                node.left_node_ref = lnode.rotate_left(self.ndb, version)
                return node.rotate_right(self.ndb, version)
        elif balance < -1:
            rbalance = (
                rnode.left_node(self.ndb).height - rnode.right_node(self.ndb).height
            )
            if rbalance < 0:
                # right right
                return node.rotate_left(self.ndb, version)
            else:
                # right left
                node.right_node_ref = rnode.rotate_right(self.ndb, version)
                return node.rotate_left(self.ndb, version)
        else:
            return node

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
            self.ndb.set(hash, node.persisted())

        if isinstance(self.root_node_ref, Node):
            self.root_node_ref = self.save_branch(self.root_node_ref, save_node)
        self.version += 1
        root_hash = self.root_node_ref or hashlib.sha256().digest()
        self.ndb.set_root_hash(self.version, root_hash)
        return root_hash
