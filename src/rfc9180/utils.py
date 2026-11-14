import base64
import binascii
import re

_B64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]*$")


def I2OSP(n: int, w: int) -> bytes:
    """
    Convert non-negative integer to a w-length big-endian byte string.

    Parameters
    ----------
    n : int
        Non-negative integer to convert.
    w : int
        Desired output length in bytes.

    Returns
    -------
    bytes
        Big-endian byte representation of n.

    Raises
    ------
    ValueError
        If n is negative or too large for w bytes.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n >= 256**w:
        raise ValueError("integer too large")
    return n.to_bytes(w, byteorder="big")


def OS2IP(x: bytes) -> int:
    """
    Convert byte string to a non-negative integer (big-endian).

    Parameters
    ----------
    x : bytes
        Byte string to convert.

    Returns
    -------
    int
        Non-negative integer value of x.
    """
    return int.from_bytes(x, byteorder="big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two equal-length byte strings.

    Parameters
    ----------
    a : bytes
        First byte string.
    b : bytes
        Second byte string.

    Returns
    -------
    bytes
        XOR of a and b.

    Raises
    ------
    ValueError
        If a and b have different lengths.
    """
    if len(a) != len(b):
        raise ValueError("Inputs must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def concat(*args: bytes) -> bytes:
    """
    Concatenate byte strings.

    Parameters
    ----------
    *args : bytes
        Variable number of byte strings to concatenate.

    Returns
    -------
    bytes
        Concatenated byte string.
    """
    return b"".join(args)


def base64url_decode(value: str) -> bytes:
    """
    Decode a base64url string (with optional omitted padding).

    Non-alphabet characters are rejected. ``"QUJD!!!!REVG"`` does not decode.

    Parameters
    ----------
    value : str
        Base64url-encoded string.

    Returns
    -------
    bytes
        Decoded bytes.

    Raises
    ------
    ValueError
        If ``value`` is not a base64url string.
    """
    if not isinstance(value, str) or _B64URL_ALPHABET.fullmatch(value) is None:
        raise ValueError("Invalid base64url string")
    if len(value) % 4 == 1:
        raise ValueError("Invalid base64url string")
    padded = value + ("=" * (-len(value) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64url string") from exc
