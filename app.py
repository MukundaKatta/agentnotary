"""agentnotary dashboard — notarize an AI agent's action log.

    pip install -e ".[dashboard]"
    streamlit run app.py

Paste an action log (one JSON object or plain line per row), get a keccak-256
Merkle root to anchor on-chain, and an inclusion proof for any single action.
Runs offline, no key.
"""

from __future__ import annotations

import json

import streamlit as st

from agentnotary import AgentNotary

SAMPLE = """{"tool": "search", "query": "flights JFK->SFO"}
{"tool": "transfer", "amount": 50, "to": "0xA11ce"}
{"tool": "email", "to": "ops@example.com", "subject": "booking confirmed"}
{"tool": "calendar", "event": "Trip", "date": "2026-06-12"}"""

st.set_page_config(page_title="agentnotary", page_icon="🔗", layout="centered")

st.title("🔗 agentnotary")
st.caption(
    "Turn an AI agent's action log into a tamper-evident, on-chain-verifiable "
    "attestation. keccak-256 Merkle root with Solidity-compatible proofs. "
    "No key, runs offline."
)

raw = st.text_area(
    "Action log (one JSON object or line per action)",
    value=SAMPLE,
    height=200,
)

if st.button("Notarize", type="primary"):
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        st.warning("Add at least one action.")
        st.stop()

    notary = AgentNotary()
    for line in lines:
        try:
            notary.record(json.loads(line))
        except json.JSONDecodeError:
            notary.record(line)  # plain text is fine too

    att = notary.attest()

    st.subheader("Attestation")
    st.metric("Actions notarized", att.leaf_count)
    st.code(att.root, language="text")
    st.caption("Anchor this root on-chain (one storage write) to commit to the whole log.")

    st.subheader("Inclusion proof")
    idx = st.number_input(
        "Action index", min_value=0, max_value=att.leaf_count - 1, value=0, step=1
    )
    proof = notary.proof(int(idx))
    ok = AgentNotary.verify(notary.leaf(int(idx)), proof, att.root)
    st.write(f"Leaf: `{notary.leaf(int(idx))}`")
    st.write(f"Proof ({len(proof)} hashes):")
    st.json(proof)
    (st.success if ok else st.error)(f"Verifies against root: {ok}")
