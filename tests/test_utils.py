import pytest

from hpke.utils import I2OSP, OS2IP, concat, xor_bytes


def test_I2OSP_and_OS2IP_roundtrip():
    assert I2OSP(0, 1) == b"\x00"
    assert I2OSP(255, 1) == b"\xff"
    assert I2OSP(256, 2) == b"\x01\x00"
    assert OS2IP(b"\x00") == 0
    assert OS2IP(b"\xff") == 255
    assert OS2IP(b"\x01\x00") == 256


def test_I2OSP_bounds():
    with pytest.raises(ValueError):
        I2OSP(-1, 1)
    with pytest.raises(ValueError):
        I2OSP(256, 1)


def test_xor_bytes():
    a = bytes.fromhex("0f0f")
    b = bytes.fromhex("f0f0")
    assert xor_bytes(a, b) == bytes.fromhex("ffff")
    with pytest.raises(ValueError):
        xor_bytes(b"\x00", b"\x00\x01")


def test_concat():
    assert concat(b"a", b"b", b"c") == b"abc"
    assert concat() == b""


