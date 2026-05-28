"""Pure-Python keccak-256 (the hash Ethereum uses).

No dependencies, so agentnotary's core runs anywhere. This is the original
Keccak padding (0x01 domain), which is what Ethereum's `keccak256` uses — not
the later SHA3-256 (0x06 domain). Correctness is pinned by published test
vectors in the test suite.
"""

from __future__ import annotations

_MASK64 = (1 << 64) - 1

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROTC = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)
_PILN = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)

_RATE = 136  # bytes (1088-bit rate for keccak-256)


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for rnd in range(24):
        # theta
        bc = [state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20] for i in range(5)]
        for i in range(5):
            t = bc[(i + 4) % 5] ^ _rol(bc[(i + 1) % 5], 1)
            for j in range(0, 25, 5):
                state[j + i] ^= t

        # rho + pi
        t = state[1]
        for i in range(24):
            j = _PILN[i]
            prev = state[j]
            state[j] = _rol(t, _ROTC[i])
            t = prev

        # chi
        for j in range(0, 25, 5):
            row = [state[j + i] for i in range(5)]
            for i in range(5):
                state[j + i] = (row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5])) & _MASK64

        # iota
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """keccak-256 digest of `data` as 32 raw bytes."""
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % _RATE != 0:
        msg.append(0x00)
    msg[-1] ^= 0x80

    state = [0] * 25
    for off in range(0, len(msg), _RATE):
        block = msg[off : off + _RATE]
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f1600(state)

    out = bytearray()
    for lane in state:
        out += lane.to_bytes(8, "little")
        if len(out) >= 32:
            break
    return bytes(out[:32])


def keccak256_hex(data: bytes, *, prefix: bool = True) -> str:
    """keccak-256 digest as a hex string, `0x`-prefixed by default."""
    digest = keccak256(data).hex()
    return f"0x{digest}" if prefix else digest
