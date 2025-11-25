from typing import Tuple

from .utils import I2OSP, concat


def append_header(enc: bytes, ct: bytes, kem_id: int, kdf_id: int, aead_id: int, mode: int) -> bytes:
    """
    Encode an HPKE message with a self-describing header.

    Format: "HPKE" | kem_id(2) | kdf_id(2) | aead_id(2) | mode(1) | enc | ct

    Parameters
    ----------
    enc : bytes
        Encapsulated public key.
    ct : bytes
        Ciphertext.
    kem_id : int
        KEM algorithm identifier (2 bytes).
    kdf_id : int
        KDF algorithm identifier (2 bytes).
    aead_id : int
        AEAD algorithm identifier (2 bytes).
    mode : int
        HPKE mode identifier (1 byte).

    Returns
    -------
    bytes
        Complete HPKE message with header.
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
    Parse a self-describing HPKE message.

    Parameters
    ----------
    msg : bytes
        Complete HPKE message with header.
    enc_len : int
        Length of the encapsulated public key (Nenc) for the specific KEM.

    Returns
    -------
    tuple
        Tuple of (kem_id, kdf_id, aead_id, mode, enc, ct).

    Raises
    ------
    ValueError
        If message is too short or has invalid magic bytes.
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


