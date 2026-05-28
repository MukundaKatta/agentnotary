# agentnotary — submission copy

**Repo:** https://github.com/MukundaKatta/agentnotary

**Target event:** ETHGlobal New York 2026 (AI x Crypto)

**Tagline:** Tamper-evident receipts for AI agent actions, verifiable on-chain.

## Short description

A pure-Python library that hashes AI agent actions into a Merkle tree and
produces one root you can anchor on-chain or sign with an Ethereum key. Proofs
verify against OpenZeppelin's `MerkleProof.verify`, so on-chain checks need no
custom cryptography.

## Inspiration

AI agents act on your behalf and leave a log you're asked to trust blindly. We
wanted to prove, after the fact, that an agent did exactly what it claims,
without trusting the server that stored the log. On a crypto stage, that means
making the proof checkable by a smart contract.

## What it does

It hashes each agent action into a leaf, builds a Merkle tree, and gives you one
root. You anchor that root on-chain or sign it with an Ethereum key. Later,
anyone can prove a single action was in the set with a Merkle proof, or show
that one was altered. The proofs verify against OpenZeppelin's
`MerkleProof.verify`, so on-chain checks need no custom cryptography.

## How we built it

Pure-Python keccak-256 written from the Keccak spec, a sorted-pair Merkle tree
that matches the OpenZeppelin convention, and optional EIP-191 sign/recover
through eth-account. Zero core dependencies. A keyless deterministic core and a
Streamlit demo.

## Challenges we ran into

Getting keccak-256 byte-exact. Ethereum uses the original Keccak padding, not
the NIST SHA-3 padding, and that one byte changes every hash. We also had to
order Merkle pairs the way OpenZeppelin does so an off-chain proof verifies
on-chain with no surprises.

## Accomplishments we're proud of

keccak passes the published Ethereum test vectors, the EIP-191 round-trip
recovers the correct signer, and proofs verify against the real OZ contract
logic, all with no web3 dependency in the core.

## What we learned

The small gap between Keccak and SHA-3 padding is the kind of thing that
silently breaks crypto. Validate against published vectors before building
anything on top.

## What's next

A one-line script to anchor a root in a real transaction, batching many agents
under one root, and a verifier contract shipped in the repo.

## Tech tags

python, ethereum, keccak-256, merkle-proof, eip-191, openzeppelin, eth-account,
ai-agents, audit-log, streamlit, mit
