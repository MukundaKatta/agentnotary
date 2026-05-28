"""agentnotary core: turn an AI agent's action log into a tamper-evident,
on-chain-verifiable attestation.

Each recorded action is canonicalized and hashed into a keccak-256 Merkle leaf.
At any point you can produce an attestation (the Merkle root + a count), a proof
that any single action is included, and — with the optional `eth` extra — an
EIP-191 signature over the root that `ecrecover` can verify on-chain.

    from agentnotary import AgentNotary

    notary = AgentNotary()
    notary.record({"tool": "transfer", "amount": 50, "to": "0xabc"})
    notary.record({"tool": "email", "to": "ops@example.com"})

    att = notary.attest()
    print(att.root, att.leaf_count)

    proof = notary.proof(0)
    assert AgentNotary.verify(notary.leaf(0), proof, att.root)
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from .merkle import merkle_proof, merkle_root, verify_proof


def _to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str[2:] if hex_str.startswith("0x") else hex_str)


def _to_hex(raw: bytes) -> str:
    return "0x" + raw.hex()


def canonical_leaf(action: dict | str) -> bytes:
    """keccak-256 leaf for an action.

    Dicts are serialized with sorted keys so the same action always hashes to
    the same leaf regardless of key order. Strings are hashed as-is.
    """
    from .keccak import keccak256

    if isinstance(action, str):
        payload = action.encode("utf-8")
    else:
        payload = json.dumps(action, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return keccak256(payload)


@dataclass
class Attestation:
    root: str
    leaf_count: int
    ts: float
    algorithm: str = "keccak256"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AgentNotary:
    """Append-only log of agent actions, attestable to a Merkle root."""

    _leaves: list[bytes] = field(default_factory=list)

    def record(self, action: dict | str) -> str:
        """Hash and append one action. Returns the leaf as 0x-hex."""
        leaf = canonical_leaf(action)
        self._leaves.append(leaf)
        return _to_hex(leaf)

    @property
    def count(self) -> int:
        return len(self._leaves)

    def leaf(self, index: int) -> str:
        """The 0x-hex leaf at `index`."""
        return _to_hex(self._leaves[index])

    def attest(self) -> Attestation:
        """Snapshot the current log as a Merkle-root attestation."""
        if not self._leaves:
            raise ValueError("nothing recorded yet")
        return Attestation(
            root=_to_hex(merkle_root(self._leaves)),
            leaf_count=len(self._leaves),
            ts=round(time.time(), 3),
        )

    def proof(self, index: int) -> list[str]:
        """Inclusion proof (list of 0x-hex sibling hashes) for action `index`."""
        return [_to_hex(node) for node in merkle_proof(self._leaves, index)]

    @staticmethod
    def verify(leaf_hex: str, proof: list[str], root_hex: str) -> bool:
        """True if `leaf_hex` is included under `root_hex` via `proof`."""
        return verify_proof(
            _to_bytes(leaf_hex), [_to_bytes(p) for p in proof], _to_bytes(root_hex)
        )

    def sign(self, private_key: str) -> str:
        """EIP-191 signature over the current root. Requires `agentnotary[eth]`."""
        from .sign import sign_root

        return sign_root(self.attest().root, private_key)
