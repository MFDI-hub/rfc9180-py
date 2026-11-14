import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import AEADID, KDFID
from rfc9180.context import ContextRecipient, ContextSender
from rfc9180.exceptions import MessageLimitReachedError, OpenError
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.utils import I2OSP, xor_bytes


def make_contexts() -> tuple[ContextSender, ContextRecipient]:
    aead = AEADBase(AEADID.AES_128_GCM)
    kdf = KDFBase(KDFID.HKDF_SHA256)
    key = secrets.token_bytes(aead.Nk)
    base_nonce = secrets.token_bytes(aead.Nn)
    suite_id = b"HPKE\x00\x00\x00\x01\x00\x01"
    exporter_secret = secrets.token_bytes(kdf.Nh)
    sender = ContextSender(
        aead=aead,
        kdf=kdf,
        key=key,
        base_nonce=base_nonce,
        exporter_secret=exporter_secret,
        suite_id=suite_id,
    )
    recipient = ContextRecipient(
        aead=aead,
        kdf=kdf,
        key=key,
        base_nonce=base_nonce,
        exporter_secret=exporter_secret,
        suite_id=suite_id,
    )
    return sender, recipient


@given(seq=st.integers(min_value=0, max_value=2**32 - 1))
@settings(max_examples=100)
def test_context_compute_nonce_deterministic(seq: int) -> None:
    sender, _ = make_contexts()
    nonce1 = sender.compute_nonce(seq)
    nonce2 = sender.compute_nonce(seq)
    assert len(nonce1) == sender.aead.Nn
    assert nonce1 == nonce2


@given(seq=st.integers(min_value=0, max_value=2**16 - 1))
@settings(max_examples=200)
def test_context_compute_nonce_matches_xor(seq: int) -> None:
    sender, _ = make_contexts()
    expected = xor_bytes(sender.base_nonce, I2OSP(seq, sender.aead.Nn))
    assert sender.compute_nonce(seq) == expected


def test_context_sequence_overflow_raises() -> None:
    sender, _ = make_contexts()
    sender.seq = sender.aead.max_seq
    with pytest.raises(MessageLimitReachedError):
        sender.increment_seq()


@given(
    aad=st.binary(min_size=0, max_size=256),
    pt=st.binary(min_size=0, max_size=512),
)
@settings(max_examples=100)
def test_context_seal_open_roundtrip_fuzz(aad: bytes, pt: bytes) -> None:
    sender, recipient = make_contexts()
    ct = sender.seal(aad, pt)
    assert recipient.open(aad, ct) == pt


@given(
    aad=st.binary(min_size=0, max_size=128),
    pt=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=100)
def test_context_modified_ciphertext_fails(aad: bytes, pt: bytes) -> None:
    sender, recipient = make_contexts()
    ct = bytearray(sender.seal(aad, pt))
    if not ct:
        pytest.skip("Ciphertext unexpectedly empty")
    idx = secrets.randbelow(len(ct))
    ct[idx] ^= 0x01
    with pytest.raises(OpenError):
        recipient.open(aad, bytes(ct))


@given(
    aad=st.binary(min_size=0, max_size=128),
    pt=st.binary(min_size=0, max_size=256),
    tampered_aad=st.binary(min_size=0, max_size=128),
)
@settings(max_examples=100)
def test_context_modified_aad_fails(aad: bytes, pt: bytes, tampered_aad: bytes) -> None:
    sender, recipient = make_contexts()
    ct = sender.seal(aad, pt)
    if aad == tampered_aad:
        pytest.skip("Tampered AAD equals original; nothing to test")
    with pytest.raises(OpenError):
        recipient.open(tampered_aad, ct)


@given(
    exporter_context=st.binary(min_size=0, max_size=64),
    L=st.integers(min_value=0, max_value=1024),
)
@settings(max_examples=100)
def test_context_export_properties(exporter_context: bytes, L: int) -> None:
    sender, recipient = make_contexts()
    max_L = 255 * sender.kdf.Nh
    if max_L < L:
        with pytest.raises(ValueError):
            sender.export(exporter_context, L)
        return
    s_val = sender.export(exporter_context, L)
    r_val = recipient.export(exporter_context, L)
    assert len(s_val) == L
    assert s_val == r_val
