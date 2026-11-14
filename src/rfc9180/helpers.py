from .constants import AEAD_PARAMS, AEADID, KEM_PARAMS, KEMID
from .utils import I2OSP, concat


def append_header(
    enc: bytes, ct: bytes, kem_id: int, kdf_id: int, aead_id: int, mode: int
) -> bytes:
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


def parse_header(msg: bytes, enc_len: int) -> tuple[int, int, int, int, bytes, bytes]:
    """
    Parse a self-describing HPKE message.

    Parameters
    ----------
    msg : bytes
        Complete HPKE message with header.
    enc_len : int
        Length of the encapsulated public key. Must equal ``Nenc`` for ``kem_id``.

    Returns
    -------
    tuple
        Tuple of (kem_id, kdf_id, aead_id, mode, enc, ct).

    Raises
    ------
    ValueError
        If the message is too short, the magic bytes are wrong, ``enc_len`` does
        not match ``kem_id``, or the ciphertext is shorter than the AEAD tag.
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

    try:
        expected_enc = KEM_PARAMS[KEMID(kem_id)]["Nenc"]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Unknown KEM id: {kem_id}") from exc
    if enc_len != expected_enc:
        raise ValueError(f"enc_len {enc_len} does not match kem_id {kem_id} (Nenc={expected_enc})")

    if len(msg) < offset + enc_len:
        raise ValueError("Message too short for enc")

    enc = msg[offset : offset + enc_len]
    ct = msg[offset + enc_len :]

    try:
        tag_len = AEAD_PARAMS[AEADID(aead_id)]["Nt"]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Unknown AEAD id: {aead_id}") from exc
    if len(ct) < tag_len:
        raise ValueError(f"Ciphertext shorter than Nt ({tag_len})")

    return kem_id, kdf_id, aead_id, mode, enc, ct
