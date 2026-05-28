"""Optional EIP-191 signing of an attestation root.

This is the only part of agentnotary that needs a dependency. Install the
`eth` extra (`pip install agentnotary[eth]`) to sign a root with an Ethereum
key and recover the signer. The signature uses the standard personal_sign
prefix, so it verifies on-chain with `ecrecover` / OpenZeppelin's ECDSA.
"""

from __future__ import annotations


def sign_root(root_hex: str, private_key: str) -> str:
    """Sign an attestation root (0x-hex) with an Ethereum private key.

    Returns the 0x-prefixed signature. Requires `agentnotary[eth]`.
    """
    from eth_account import Account
    from eth_account.messages import encode_defunct

    message = encode_defunct(hexstr=root_hex)
    signed = Account.sign_message(message, private_key=private_key)
    return signed.signature.hex()


def recover_signer(root_hex: str, signature: str) -> str:
    """Recover the signer's checksummed address from a root + signature.

    Requires `agentnotary[eth]`.
    """
    from eth_account import Account
    from eth_account.messages import encode_defunct

    message = encode_defunct(hexstr=root_hex)
    return Account.recover_message(message, signature=signature)
