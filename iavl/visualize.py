import binascii
from typing import List

from graphviz import Digraph
from hexbytes import HexBytes

from .utils import Node, decode_node, node_key


def label(node: Node):
    s = binascii.hexlify(node.key).decode()
    if len(s) > 10:
        s = s[:4] + "..." + s[-4:]
    s = f"{node.version}: {s}"
    if node.is_leaf():
        s += f"\nvalue len: {len(node.value)}"
    else:
        s += f"\nheight: {node.height}"
    return s


def visualize_iavl(
    db, prefix: bytes, root_hash: bytes, version: int, root_hash2=None
) -> Digraph:
    g = Digraph(comment="IAVL Tree")

    def get_node(hash: bytes) -> Node:
        n, _ = decode_node(db.get(prefix + node_key(hash)), hash)
        return n

    def vis_node(hash: bytes, n: Node):
        style = "solid" if n.version == version else "filled"
        g.node(HexBytes(hash).hex(), label=label(node), style=style)

    if root_hash2 is not None:
        stack: List[bytes] = [root_hash2]
        while stack:
            hash = stack.pop()
            node = get_node(hash)

            vis_node(hash, node)

            if not node.is_leaf():
                stack.append(node.right_node_ref)
                stack.append(node.left_node_ref)

                g.edges(
                    [
                        (HexBytes(hash).hex(), HexBytes(node.right_node_ref).hex()),
                        (HexBytes(hash).hex(), HexBytes(node.left_node_ref).hex()),
                    ]
                )

    stack: List[bytes] = [root_hash]
    while stack:
        hash = stack.pop()
        node = get_node(hash)

        # don't duplicate nodes in compare mode
        if root_hash2 is None or node.version == version:
            vis_node(hash, node)

        if not node.is_leaf():
            stack.append(node.right_node_ref)
            stack.append(node.left_node_ref)

            # don't duplicate edges in compare mode
            if root_hash2 is None or node.version == version:
                g.edges(
                    [
                        (HexBytes(hash).hex(), HexBytes(node.right_node_ref).hex()),
                        (HexBytes(hash).hex(), HexBytes(node.left_node_ref).hex()),
                    ]
                )

    return g
