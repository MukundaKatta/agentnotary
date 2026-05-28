"""A keccak-256 Merkle tree with sorted-pair hashing.

Sorted-pair hashing (hash the two children in ascending byte order) is the same
convention OpenZeppelin's `MerkleProof` uses on-chain, so a proof produced here
verifies in a Solidity contract unchanged. Odd nodes are carried up a level.
"""

from __future__ import annotations

from .keccak import keccak256


def hash_pair(a: bytes, b: bytes) -> bytes:
    """Hash two 32-byte nodes in ascending order (OpenZeppelin convention)."""
    return keccak256(a + b) if a <= b else keccak256(b + a)


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root of the tree over `leaves`. Requires at least one leaf."""
    if not leaves:
        raise ValueError("cannot build a Merkle tree with no leaves")
    layer = list(leaves)
    while len(layer) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(hash_pair(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])  # odd node carried up
        layer = nxt
    return layer[0]


def merkle_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Sibling hashes proving `leaves[index]` is under the root, leaf->root."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    proof: list[bytes] = []
    layer = list(leaves)
    idx = index
    while len(layer) > 1:
        sibling = idx ^ 1
        if sibling < len(layer):
            proof.append(layer[sibling])
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                nxt.append(hash_pair(layer[i], layer[i + 1]))
            else:
                nxt.append(layer[i])
        layer = nxt
        idx //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    """True if `proof` carries `leaf` up to `root` under sorted-pair hashing."""
    node = leaf
    for sibling in proof:
        node = hash_pair(node, sibling)
    return node == root
