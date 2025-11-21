import secrets

from hpke.constants import AEADID, KDFID
from hpke.context import ContextRecipient, ContextSender
from hpke.primitives.aead import AEADBase
from hpke.primitives.kdf import KDFBase
from hpke.utils import I2OSP, xor_bytes


def test_context_nonce_computation():
    aead = AEADBase(AEADID.AES_128_GCM)
    kdf = KDFBase(KDFID.HKDF_SHA256)
    key = b"\x00" * aead.Nk
    base_nonce = b"\x01" * aead.Nn
    suite_id = b"HPKE\x00\x00\x00\x01\x00\x01"  # arbitrary
    sender = ContextSender(aead=aead, kdf=kdf, key=key, base_nonce=base_nonce, exporter_secret=b"\x00" * kdf.Nh, suite_id=suite_id)
    nonce0 = sender.compute_nonce(0)
    assert nonce0 == base_nonce
    nonce1 = sender.compute_nonce(1)
    assert nonce1 == xor_bytes(base_nonce, I2OSP(1, aead.Nn))


def test_context_seal_open_roundtrip():
    aead = AEADBase(AEADID.AES_128_GCM)
    kdf = KDFBase(KDFID.HKDF_SHA256)
    key = secrets.token_bytes(aead.Nk)
    base_nonce = secrets.token_bytes(aead.Nn)
    suite_id = b"HPKE\x00\x00\x00\x01\x00\x01"
    exp = secrets.token_bytes(kdf.Nh)
    sender = ContextSender(aead=aead, kdf=kdf, key=key, base_nonce=base_nonce, exporter_secret=exp, suite_id=suite_id)
    recipient = ContextRecipient(aead=aead, kdf=kdf, key=key, base_nonce=base_nonce, exporter_secret=exp, suite_id=suite_id)
    aad = b""
    pt1 = b"hello"
    pt2 = b"world"
    ct1 = sender.seal(aad, pt1)
    ct2 = sender.seal(aad, pt2)
    assert recipient.open(aad, ct1) == pt1
    assert recipient.open(aad, ct2) == pt2


