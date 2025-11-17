import struct
from typing import Tuple

from .utils import I2OSP, concat


def append_header(enc: bytes, ct: bytes, kem_id: int, kdf_id: int, aead_id: int, mode: int) -> bytes:
    """
    Encodes an HPKE message with a self-describing header.
    Format: "HPKE" | kem_id(2) | kdf_id(2) | aead_id(2) | mode(1) | enc | ct
    """
    header = concat(
        b"HPKE",
        I2OSP(kem_id, 2),
        I2OSP(kdf_id, 2),
        I2OSP(aead_id, 2),
        I2OSP(mode, 1),
    )
    return header + enc + ct


def parse_header(msg: bytes, enc_len: int) -> Tuple[int, int, int, int, bytes, bytes]:
    """
    Parses a self-describing HPKE message.
    Returns: (kem_id, kdf_id, aead_id, mode, enc, ct)
    Requires knowledge of enc_len (Nenc) for the specific KEM to split enc/ct.
    """
    if len(msg) < 4 + 2 + 2 + 2 + 1:
        raise ValueError("Message too short for header")

    magic = msg[:4]
    if magic != b"HPKE":
        raise ValueError("Invalid magic bytes")

    offset = 4
    kem_id = int.from_bytes(msg[offset : offset + 2], "big")
    offset += 2
    kdf_id = int.from_bytes(msg[offset : offset + 2], "big")
    offset += 2
    aead_id = int.from_bytes(msg[offset : offset + 2], "big")
    offset += 2
    mode = int.from_bytes(msg[offset : offset + 1], "big")
    offset += 1

    if len(msg) < offset + enc_len:
        raise ValueError("Message too short for enc")

    enc = msg[offset : offset + enc_len]
    ct = msg[offset + enc_len :]

    return kem_id, kdf_id, aead_id, mode, enc, ct


