# agentnotary 🔗

Make an AI agent's actions **provable**. `agentnotary` turns an agent's action
log into a tamper-evident, on-chain-verifiable attestation: every action is a
keccak-256 Merkle leaf, the **root** is one 32-byte commitment you can anchor on
Ethereum, and anyone can later prove a specific action was — or was not — in the
log. The core has **zero dependencies and needs no key**, so it runs anywhere.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-pytest-blueviolet.svg)](tests/)
[![keccak-256](https://img.shields.io/badge/hash-keccak--256-purple.svg)](src/agentnotary/keccak.py)

---

## Why

As agents start moving money, sending mail, and calling tools on our behalf,
"trust me, that's what it did" is not good enough. You want a commitment you
made *before* anyone asked questions, that you cannot quietly edit after the
fact. A Merkle root anchored on-chain is exactly that:

- **One cheap write.** Anchor a single 32-byte root, not the whole log.
- **Prove any action later.** A short inclusion proof shows action *k* was in
  the committed set. Change one byte of one action and the proof fails.
- **Solidity-native.** Sorted-pair keccak-256 hashing matches OpenZeppelin's
  `MerkleProof`, so the same proof verifies in a contract unchanged.
- **Signable.** Optionally sign the root with EIP-191 so `ecrecover` can prove
  *which* agent/operator committed it.

## Quickstart (no key, no deps)

```bash
pip install -e .
python examples/demo.py
```

```python
from agentnotary import AgentNotary

notary = AgentNotary()
notary.record({"tool": "transfer", "amount": 50, "to": "0xA11ce"})
notary.record({"tool": "email", "to": "ops@example.com"})

att = notary.attest()
print(att.root)        # 0x… anchor this on-chain
print(att.leaf_count)  # 2

# Later: prove action #0 was in the committed log.
proof = notary.proof(0)
assert AgentNotary.verify(notary.leaf(0), proof, att.root)
```

## Verify on-chain

The root and proofs use sorted-pair keccak-256, the OpenZeppelin convention:

```solidity
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

// `root` was anchored earlier; `leaf` and `proof` come from agentnotary.
require(MerkleProof.verify(proof, root, leaf), "action not in committed log");
```

## Sign the root (optional)

```bash
pip install -e ".[eth]"
```

```python
from agentnotary import AgentNotary
from agentnotary.sign import recover_signer

notary = AgentNotary()
notary.record({"tool": "transfer", "amount": 50})
sig = notary.sign(private_key="0x…")          # EIP-191 personal_sign over the root
who = recover_signer(notary.attest().root, sig)  # checksummed signer address
```

The signature uses the standard personal_sign prefix, so the same recovery works
on-chain with `ecrecover` / OpenZeppelin's `ECDSA`.

## How it works

```
action 0 ─ keccak256 ─┐
action 1 ─ keccak256 ─┤─ hash_pair ─┐
action 2 ─ keccak256 ─┐             ├─ root  (0x…32 bytes)
action 3 ─ keccak256 ─┘─ hash_pair ─┘
                                     │
                              anchor on-chain  +  optional EIP-191 signature
```

- `keccak.py` — pure-Python keccak-256, pinned to published Ethereum test
  vectors so the hash can never silently drift.
- `merkle.py` — sorted-pair Merkle root, proof, and verify (Solidity-compatible).
- `notary.py` — canonicalizes each action (dicts hash key-order-independently),
  records, attests, proves, and verifies.
- `sign.py` — optional EIP-191 signing/recovery via `eth-account`.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite pins keccak-256 to known vectors and round-trips Merkle proofs for
every leaf, including odd-sized trees. Runs fully offline.

## License

MIT — see [LICENSE](LICENSE).
