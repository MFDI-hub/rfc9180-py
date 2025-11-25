
import pytest
import secrets
from rfc9180.constants import AEADID
from rfc9180.primitives.aead import AEADBase


def test_aes128gcm_seal_open_roundtrip():
    aead = AEADBase(AEADID.AES_128_GCM)
    key = secrets.token_bytes(aead.Nk)
    nonce = secrets.token_bytes(aead.Nn)
    aad = b"header"
    pt = b"hello world"
    ct = aead.seal(key, nonce, aad, pt)
    assert isinstance(ct, bytes)
    pt2 = aead.open(key, nonce, aad, ct)
    assert pt2 == pt


def test_chacha20poly1305_roundtrip():
    aead = AEADBase(AEADID.CHACHA20_POLY1305)
    key = secrets.token_bytes(aead.Nk)
    nonce = secrets.token_bytes(aead.Nn)
    aad = b""
    pt = b"msg"
    ct = aead.seal(key, nonce, aad, pt)
    assert aead.open(key, nonce, aad, ct) == pt


def test_export_only_rejects_seal_open():
    aead = AEADBase(AEADID.EXPORT_ONLY)
    with pytest.raises(ValueError):
        aead.seal(b"", b"", b"", b"")
    with pytest.raises(ValueError):
        aead.open(b"", b"", b"", b"")


