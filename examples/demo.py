"""agentnotary demo — runs offline, no key, no dependencies.

    python examples/demo.py

Notarizes an AI agent's action log: records a few actions, attests to a
keccak-256 Merkle root, proves one action is included, and shows that tampering
breaks the proof.
"""

from __future__ import annotations

from agentnotary import AgentNotary

ACTIONS = [
    {"tool": "search", "query": "flights JFK->SFO"},
    {"tool": "transfer", "amount": 50, "to": "0xA11ce"},
    {"tool": "email", "to": "ops@example.com", "subject": "booking confirmed"},
    {"tool": "calendar", "event": "Trip", "date": "2026-06-12"},
]


def main() -> None:
    notary = AgentNotary()
    print("Recording agent actions:")
    for action in ACTIONS:
        leaf = notary.record(action)
        print(f"  {leaf[:18]}…  {action}")

    att = notary.attest()
    print()
    print("Attestation (anchor this root on-chain):")
    print(f"  root:    {att.root}")
    print(f"  actions: {att.leaf_count}")
    print(f"  algo:    {att.algorithm}")

    idx = 1
    proof = notary.proof(idx)
    print()
    print(f"Inclusion proof for action #{idx} ({len(proof)} hashes):")
    for node in proof:
        print(f"  {node}")
    ok = AgentNotary.verify(notary.leaf(idx), proof, att.root)
    print(f"  verifies against root: {ok}")

    # Tamper check: a forged action with the real proof must fail.
    forged = AgentNotary.verify(
        AgentNotary().record({"tool": "transfer", "amount": 5000, "to": "0xBADbad"}),
        proof,
        att.root,
    )
    print(f"  forged action verifies: {forged}  (expected False)")


if __name__ == "__main__":
    main()
