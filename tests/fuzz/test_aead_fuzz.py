import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import AEADID
from rfc9180.exceptions import OpenError
from rfc9180.primitives.aead import AEADBase


def aead_strategies() -> st.SearchStrategy[AEADBase]:
    return st.sampled_from(
        [
            AEADBase(AEADID.AES_128_GCM),
            AEADBase(AEADID.AES_256_GCM),
            AEADBase(AEADID.CHACHA20_POLY1305),
        ]
    )


@given(
    aead=aead_strategies(),
    key=st.binary(min_size=0, max_size=64),
    nonce=st.binary(min_size=0, max_size=32),
)
@settings(max_examples=100)
def test_aead_key_nonce_length_validation(aead: AEADBase, key: bytes, nonce: bytes) -> None:
    aad = b""
    pt = b"msg"
    if len(key) != aead.Nk or len(nonce) != aead.Nn:
        with pytest.raises(ValueError):
            aead.seal(key, nonce, aad, pt)
        with pytest.raises(ValueError):
            aead.open(key, nonce, aad, b"")
    else:
        ct = aead.seal(key, nonce, aad, pt)
        assert aead.open(key, nonce, aad, ct) == pt


@given(
    aead=aead_strategies(),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=100)
def test_aead_ciphertext_tampering_fails(aead: AEADBase, aad: bytes, pt: bytes) -> None:
    key = secrets.token_bytes(aead.Nk)
    nonce = secrets.token_bytes(aead.Nn)
    ct = bytearray(aead.seal(key, nonce, aad, pt))
    if not ct:
        pytest.skip("Ciphertext unexpectedly empty")
    idx = secrets.randbelow(len(ct))
    ct[idx] ^= 0x01
    with pytest.raises(OpenError):
        aead.open(key, nonce, aad, bytes(ct))


@given(
    aead=aead_strategies(),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
    bad_aad=st.binary(min_size=0, max_size=64),
)
@settings(max_examples=100)
def test_aead_aad_tampering_fails(aead: AEADBase, aad: bytes, pt: bytes, bad_aad: bytes) -> None:
    if aad == bad_aad:
        pytest.skip("Bad AAD equals original; nothing to test")
    key = secrets.token_bytes(aead.Nk)
    nonce = secrets.token_bytes(aead.Nn)
    ct = aead.seal(key, nonce, aad, pt)
    with pytest.raises(OpenError):
        aead.open(key, nonce, bad_aad, ct)


def test_aead_export_only_rejects_seal_open() -> None:
    aead = AEADBase(AEADID.EXPORT_ONLY)
    with pytest.raises(ValueError):
        aead.seal(b"", b"", b"", b"")
    with pytest.raises(ValueError):
        aead.open(b"", b"", b"", b"")
