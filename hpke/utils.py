def I2OSP(n: int, w: int) -> bytes:
    """
    Convert non-negative integer to a w-length big-endian byte string.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n >= 256 ** w:
        raise ValueError("integer too large")
    return n.to_bytes(w, byteorder='big')


def OS2IP(x: bytes) -> int:
    """
    Convert byte string to a non-negative integer (big-endian).
    """
    return int.from_bytes(x, byteorder='big')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two equal-length byte strings.
    """
    if len(a) != len(b):
        raise ValueError("Inputs must have equal length")
    return bytes(x ^ y for x, y in zip(a, b))


def concat(*args: bytes) -> bytes:
    """
    Concatenate byte strings.
    """
    return b''.join(args)


