"""agentnotary — tamper-evident, on-chain-verifiable attestations for AI agent
action logs. keccak-256 Merkle root + optional EIP-191 signing. The core runs
with no dependencies and no key."""

from __future__ import annotations

from .keccak import keccak256, keccak256_hex
from .merkle import hash_pair, merkle_proof, merkle_root, verify_proof
from .notary import AgentNotary, Attestation, canonical_leaf

__version__ = "0.1.0"

__all__ = [
    "AgentNotary",
    "Attestation",
    "canonical_leaf",
    "keccak256",
    "keccak256_hex",
    "merkle_root",
    "merkle_proof",
    "verify_proof",
    "hash_pair",
    "__version__",
]
