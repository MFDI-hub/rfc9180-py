from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.utils import I2OSP, OS2IP, base64url_decode, concat, xor_bytes


@given(
    n=st.integers(min_value=0, max_value=2**64 - 1),
    w=st.integers(min_value=1, max_value=8),
)
@settings(max_examples=100)
def test_i2osp_os2ip_roundtrip(n: int, w: int) -> None:
    max_val = 256**w - 1
    if n > max_val:
        from pytest import raises

        with raises(ValueError):
            I2OSP(n, w)
        return
    b = I2OSP(n, w)
    assert OS2IP(b) == n


@given(
    a=st.binary(min_size=0, max_size=128),
    b=st.binary(min_size=0, max_size=128),
)
@settings(max_examples=100)
def test_xor_bytes_properties(a: bytes, b: bytes) -> None:
    from pytest import raises

    if len(a) != len(b):
        with raises(ValueError):
            xor_bytes(a, b)
        return
    x = xor_bytes(a, b)
    assert len(x) == len(a)
    assert xor_bytes(a, x) == b


@given(
    parts=st.lists(st.binary(min_size=0, max_size=32), min_size=0, max_size=10),
)
@settings(max_examples=100)
def test_concat_behavior(parts: list[bytes]) -> None:
    out = concat(*parts)
    assert len(out) == sum(len(p) for p in parts)


@given(
    data=st.binary(min_size=0, max_size=64),
)
@settings(max_examples=100)
def test_base64url_decode_lenient(data: bytes) -> None:
    import base64

    encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    decoded = base64url_decode(encoded)
    assert decoded == data

