"""
Support modify iavl tree
"""
import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Union

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
    cache: Dict[bytes, PersistedNode]
    prefix: bytes

    def __init__(self, db, prefix=b""):
        self.db = db
        self.batch = None
        self.cache = {}
        self.prefix = prefix

    def get(self, hash: bytes) -> Optional[PersistedNode]:
        try:
            return self.cache[hash]
        except KeyError:
            bz = self.db.get(self.prefix + node_key(hash))
            if bz is None:
                return
            node = PersistedNode.decode(bz, hash)
            self.cache[hash] = node
            return node

    def resolve_node(self, ref: NodeRef) -> Union["Node", PersistedNode, None]:
        if isinstance(ref, Node):
            return ref
        elif ref is not None:
            return self.get(ref)

    def batch_remove_node(self, hash: bytes):
        "remove node"
        if self.batch is None:
            self.batch = rocksdb.WriteBatch()
        self.batch.delete(node_key(hash))
        self.cache.pop(hash, None)

    def batch_remove_root_hash(self, version: int):
        if self.batch is None:
            self.batch = rocksdb.WriteBatch()
        self.batch.delete(root_key(version))

    def batch_set_node(self, hash: bytes, node: PersistedNode):
        if self.batch is None:
            self.batch = rocksdb.WriteBatch()
        self.cache[hash] = node
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
        return self.db.get(self.prefix + root_key(version))

    def get_root_node(self, version: int) -> Optional[PersistedNode]:
        h = self.get_root_hash(version)
        if h is None:
            return None
        return self.get(h)

    def latest_version(self) -> Optional[int]:
        from .utils import iavl_latest_version

        return iavl_latest_version(self.db, None)

    def next_version(self, v: int) -> Optional[int]:
        """
        return the first version larger than v
        """
        it = self.db.iterkeys()
        target = self.prefix + root_key(v)
        it.seek(target)
        k = next(it, None)
        if k is None:
            return
        if k == target:
            k = next(it, None)
            if k is None:
                return
        if not k.startswith(self.prefix + b"r"):
            return

        return int.from_bytes(k[len(self.prefix) + 1 :], "big")

    def prev_version(self, v: int) -> Optional[int]:
        """
        return the closest version that's smaller than the target
        """
        it = reversed(self.db.iterkeys())
        target = self.prefix + root_key(v)
        it.seek_for_prev(target)
        key = next(it, None)
        if key == target:
            key = next(it, None)
        if key is None or not key.startswith(self.prefix + b"r"):
            return
        return int.from_bytes(key[len(self.prefix) + 1 :], "big")

    def delete_version(self, v: int) -> int:
        """
        return how many nodes deleted
        """
        from .diff import diff_tree

        counter = 0
        # optimize the case when deleting from the beginning,
        # in that case, the previous version will always be 0.
        prev_version = self.prev_version(v) or 0
        root1 = self.get_root_node(v)
        root2 = self.get_root_node(self.next_version(v))
        for orphaned, _ in diff_tree(self.get, root1, root2):
            for n in orphaned:
                if n.version > prev_version or not self.get_root_hash(n.version):
                    # delete if the version don't exists anymore
                    # TODO improve performance by cache the root information
                    self.batch_remove_node(n.hash)
                    counter += 1

        self.batch_remove_root_hash(v)
        self.batch_commit()
        return counter


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
        node: PersistedNode,
        version: int,
    ):
        """
        clone a persisted branch node and prepare to modify
        """
        return cls(
            height=node.height,
            size=node.size,
            version=version,
            key=node.key,
            left_node_ref=node.left_node_ref,
            right_node_ref=node.right_node_ref,
        )

    def persisted(self, hash: bytes) -> PersistedNode:
        return PersistedNode(
            height=self.height,
            size=self.size,
            version=self.version,
            key=self.key,
            value=self.value,
            left_node_ref=self.left_node_ref,
            right_node_ref=self.right_node_ref,
            hash=hash,
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
        if isinstance(rnode, PersistedNode):
            rnode = Node.from_branch_node(rnode, version)
        rnode.left_node_ref = self
        self.update_height_size(ndb)
        rnode.update_height_size(ndb)
        return rnode

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
        if isinstance(lnode, PersistedNode):
            lnode = Node.from_branch_node(lnode, version)
        lnode.right_node_ref = self
        self.update_height_size(ndb)
        lnode.update_height_size(ndb)
        return lnode

    def update_height_size(self, ndb: NodeDB):
        lnode = self.left_node(ndb)
        rnode = self.right_node(ndb)
        self.height = max(lnode.height, rnode.height) + 1
        self.size = lnode.size + rnode.size

    def calc_balance(self, ndb: NodeDB):
        return self.left_node(ndb).height - self.right_node(ndb).height

    def balance(self, ndb: NodeDB, version: int):
        balance = self.calc_balance(ndb)
        if balance > 1:
            lnode = self.left_node(ndb)
            lbalance = lnode.calc_balance(ndb)
            if lbalance >= 0:
                # left left
                return self.rotate_right(ndb, version)
            else:
                # left right
                if isinstance(lnode, PersistedNode):
                    lnode = Node.from_branch_node(lnode, version)
                self.left_node_ref = lnode.rotate_left(ndb, version)
                return self.rotate_right(ndb, version)
        elif balance < -1:
            rnode = self.right_node(ndb)
            rbalance = rnode.calc_balance(ndb)
            if rbalance <= 0:
                # right right
                return self.rotate_left(ndb, version)
            else:
                # right left
                if isinstance(rnode, PersistedNode):
                    rnode = Node.from_branch_node(rnode, version)
                self.right_node_ref = rnode.rotate_right(ndb, version)
                return self.rotate_left(ndb, version)
        else:
            return self

    def save(self, save_node: Callable[[bytes, "Node"], None]) -> bytes:
        """
        traverse the working nodes to update hashes and save nodes
        """
        if isinstance(self.left_node_ref, Node):
            self.left_node_ref = self.left_node_ref.save(save_node)
        if isinstance(self.right_node_ref, Node):
            self.right_node_ref = self.right_node_ref.save(save_node)

        hash = self.hash()
        save_node(hash, self)
        return hash


class Tree:
    ndb: NodeDB
    root_node_ref: Union[None, bytes, Node]
    version: int

    def __init__(self, ndb: NodeDB, version: Optional[int] = None):
        self.ndb = ndb
        if version is None:
            version = ndb.latest_version()
            if version is None:
                version = 0
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
        value, new = remove_recursive(
            self.ndb, key, self.root_node_ref, self.version + 1
        )
        if value is None:
            # nothing changed
            return
        self.root_node_ref = new
        return value

    def save_version(self, dry_run=False):
        """
        if dry_run=True, don't actually modify anything, just return the new root hash
        """

        def save_node(hash: bytes, node: Node):
            if not dry_run:
                self.ndb.batch_set_node(hash, node.persisted(hash))

        if isinstance(self.root_node_ref, Node):
            self.root_node_ref = self.root_node_ref.save(save_node)
        root_hash = self.root_node_ref or hashlib.sha256().digest()
        if not dry_run:
            self.version += 1
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
            return None, None

        if new_child is None:
            # return the other child
            if turn_left:
                return value, node.right_node_ref
            else:
                return value, node.left_node_ref
        else:
            # update the subtree
            if isinstance(node, PersistedNode):
                node = Node.from_branch_node(node, version)
            if turn_left:
                node.left_node_ref = new_child
            else:
                node.right_node_ref = new_child
            node.update_height_size(ndb)
            return value, node.balance(ndb, version)


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
                    key=node.key,
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
        if isinstance(node, PersistedNode):
            node = Node.from_branch_node(node, version)
        if key < node.key:
            node.left_node_ref, updated = set_recursive(
                ndb, node.left_node_ref, key, value, version
            )
        else:
            node.right_node_ref, updated = set_recursive(
                ndb, node.right_node_ref, key, value, version
            )

        if not updated:
            # tree shape is changed, re-balance
            node.update_height_size(ndb)
            node = node.balance(ndb, version)

        return node, updated


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
