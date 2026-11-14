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


_B64URL_INDEX = {
    char: index
    for index, char in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
}


def base64url_decode(value: str) -> bytes:
    """
    Decode an unpadded base64url string.

    This is the JWK alphabet: ``A-Z``, ``a-z``, ``0-9``, ``-``, ``_``, with
    no ``=`` padding. ``"QUJD="`` is rejected. Non-alphabet characters are
    rejected, so ``"QUJD!!!!REVG"`` does not decode. A final quantum whose
    unused bits are non-zero is rejected (RFC 4648 §3.5); ``"QR"`` is rejected
    and ``"QQ"`` decodes to ``b"A"``.

    Parameters
    ----------
    value : str
        Unpadded base64url-encoded string.

    Returns
    -------
    bytes
        Decoded bytes.

    Raises
    ------
    ValueError
        If ``value`` is not canonical unpadded base64url.
    """
    if not isinstance(value, str) or _B64URL_ALPHABET.fullmatch(value) is None:
        raise ValueError("Invalid base64url string")
    remainder = len(value) % 4
    if remainder == 1:
        raise ValueError("Invalid base64url string")
    if remainder == 2 and _B64URL_INDEX[value[-1]] & 0x0F:
        raise ValueError("Invalid base64url string")
    if remainder == 3 and _B64URL_INDEX[value[-1]] & 0x03:
        raise ValueError("Invalid base64url string")
    padded = value + ("=" * (-len(value) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64url string") from exc
