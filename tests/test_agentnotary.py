"""agentnotary test suite. The core runs with no dependencies and no key.

keccak-256 correctness is pinned by published Ethereum test vectors so the
hand-written hash can never silently drift.
"""

from __future__ import annotations

import pytest

from agentnotary import (
    AgentNotary,
    canonical_leaf,
    keccak256_hex,
    merkle_proof,
    merkle_root,
    verify_proof,
)

# ---- keccak-256 vectors ----------------------------------------------------

KECCAK_VECTORS = {
    b"": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    b"abc": "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
    b"hello": "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
}


@pytest.mark.parametrize("data,expected", list(KECCAK_VECTORS.items()))
def test_keccak256_matches_ethereum_vectors(data, expected):
    assert keccak256_hex(data) == expected


def test_keccak256_hex_prefix_toggle():
    assert keccak256_hex(b"", prefix=False) == keccak256_hex(b"")[2:]


# ---- merkle tree -----------------------------------------------------------


def test_single_leaf_root_is_the_leaf():
    leaf = canonical_leaf("only")
    assert merkle_root([leaf]) == leaf


def test_pair_hashing_is_order_independent():
    a, b = canonical_leaf("a"), canonical_leaf("b")
    assert merkle_root([a, b]) == merkle_root([b, a])


def test_proof_round_trips_for_every_leaf():
    leaves = [canonical_leaf(f"action-{i}") for i in range(7)]  # odd count
    root = merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        assert verify_proof(leaf, merkle_proof(leaves, i), root)


def test_tampered_leaf_fails_verification():
    leaves = [canonical_leaf(f"action-{i}") for i in range(5)]
    root = merkle_root(leaves)
    proof = merkle_proof(leaves, 0)
    assert not verify_proof(canonical_leaf("forged"), proof, root)


def test_empty_tree_raises():
    with pytest.raises(ValueError):
        merkle_root([])


# ---- canonicalization ------------------------------------------------------


def test_dict_leaf_is_key_order_independent():
    assert canonical_leaf({"a": 1, "b": 2}) == canonical_leaf({"b": 2, "a": 1})


def test_different_actions_have_different_leaves():
    assert canonical_leaf({"tool": "x"}) != canonical_leaf({"tool": "y"})


# ---- notary end-to-end -----------------------------------------------------


def test_notary_records_and_attests():
    notary = AgentNotary()
    notary.record({"tool": "transfer", "amount": 50, "to": "0xabc"})
    notary.record({"tool": "email", "to": "ops@example.com"})

    att = notary.attest()
    assert att.leaf_count == 2
    assert att.algorithm == "keccak256"
    assert att.root.startswith("0x") and len(att.root) == 66


def test_notary_inclusion_proof_verifies():
    notary = AgentNotary()
    for i in range(4):
        notary.record({"step": i})
    att = notary.attest()
    proof = notary.proof(2)
    assert AgentNotary.verify(notary.leaf(2), proof, att.root)


def test_attest_is_deterministic():
    def build():
        n = AgentNotary()
        n.record({"tool": "a"})
        n.record({"tool": "b"})
        return n.attest().root

    assert build() == build()


def test_attest_before_record_raises():
    with pytest.raises(ValueError):
        AgentNotary().attest()


def test_to_dict_has_root_and_count():
    notary = AgentNotary()
    notary.record("x")
    d = notary.attest().to_dict()
    assert "root" in d and d["leaf_count"] == 1
