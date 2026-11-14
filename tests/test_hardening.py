"""Regression tests for secret handling, nonce use, and error types."""

import gc
import threading

import pytest

from rfc9180 import HPKE
from rfc9180.constants import AEADID, KDFID, KEMID, HPKEMode
from rfc9180.exceptions import (
    DeserializeError,
    MessageLimitReachedError,
    ValidationError,
)
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kem import DHKEM_X448, DHKEM_X25519


def test_derived_private_key_round_trip_uses_raw_bytes() -> None:
    kem = DHKEM_X25519()
    assert not hasattr(kem, "_raw_private_bytes")
    ikm = bytes(range(32))
    sk, _pk = kem.derive_key_pair(ikm)
    raw = sk.private_bytes_raw()
    assert kem.serialize_private_key(sk) == raw
    del sk
    gc.collect()
    other = bytes(b ^ 0xFF for b in raw)
    sk2 = kem.deserialize_private_key(other)
    assert kem.serialize_private_key(sk2) == other


def test_x448_serialize_private_key_matches_raw_bytes() -> None:
    kem = DHKEM_X448()
    ikm = bytes(range(56))
    sk, _pk = kem.derive_key_pair(ikm)
    assert kem.serialize_private_key(sk) == sk.private_bytes_raw()


def test_serialize_rejects_wrong_length_and_invalid_point() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    with pytest.raises(DeserializeError):
        hpke.serialize_public_key(b"\x00" * 31)
    with pytest.raises(DeserializeError):
        hpke.serialize_private_key(b"\x00" * 31)

    p256 = HPKE(KEMID.DHKEM_P256_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    with pytest.raises(DeserializeError):
        p256.serialize_public_key(b"\x00" * p256.kem.Npk)


def test_aead_message_limits() -> None:
    assert AEADBase(AEADID.AES_128_GCM).max_seq == 1 << 32
    assert AEADBase(AEADID.AES_256_GCM).max_seq == 1 << 32
    assert AEADBase(AEADID.CHACHA20_POLY1305).max_seq == (1 << 96) - 1


def test_seal_checks_message_limit_before_encrypting() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    _sk, pk = hpke.generate_key_pair()
    _enc, sender = hpke.setup.setup_base_sender(pk, b"info")
    calls: list[bytes] = []
    original = sender.aead.seal

    def spy(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        calls.append(nonce)
        return original(key, nonce, aad, pt)

    sender.aead.seal = spy  # type: ignore[method-assign]
    sender.seq = sender.aead.max_seq
    with pytest.raises(MessageLimitReachedError):
        sender.seal(b"", b"one")
    with pytest.raises(MessageLimitReachedError):
        sender.seal(b"", b"two")
    assert calls == []
    assert sender.seq == sender.aead.max_seq


def test_seal_type_error_is_not_a_message_limit() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    _sk, pk = hpke.generate_key_pair()
    _enc, sender = hpke.setup.setup_base_sender(pk, b"info")
    with pytest.raises(TypeError):
        sender.seal(b"", "not-bytes")  # type: ignore[arg-type]
    assert sender.seq == 0


def test_concurrent_seal_uses_distinct_nonces() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    sk, pk = hpke.generate_key_pair()
    enc, sender = hpke.setup.setup_base_sender(pk, b"info")
    recipient = hpke.setup.setup_base_recipient(enc, sk, b"info")
    nonces: list[bytes] = []
    ciphertexts: list[bytes] = []
    record = threading.Lock()
    original = sender.aead.seal

    def spy(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        with record:
            nonces.append(nonce)
        return original(key, nonce, aad, pt)

    sender.aead.seal = spy  # type: ignore[method-assign]
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def worker(pt: bytes) -> None:
        try:
            barrier.wait()
            ct = sender.seal(b"aad", pt)
            with record:
                ciphertexts.append(ct)
        except Exception as exc:
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(b"left",)),
        threading.Thread(target=worker, args=(b"right",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(set(nonces)) == 2
    assert sender.seq == 2
    opened = {recipient.open(b"aad", ct) for ct in ciphertexts}
    assert opened == {b"left", b"right"}


def test_short_psk_is_accepted_when_inputs_match() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    sk, pk = hpke.generate_key_pair()
    psk = b"\x01"
    psk_id = b"id"
    enc, sender = hpke.setup.setup_psk_sender(pk, b"info", psk, psk_id)
    recipient = hpke.setup.setup_psk_recipient(enc, sk, b"info", psk, psk_id)
    ct = sender.seal(b"", b"pt")
    assert recipient.open(b"", ct) == b"pt"


def test_key_schedule_rejects_unknown_role() -> None:
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    with pytest.raises(ValueError, match="role"):
        hpke.setup.key_schedule("X", HPKEMode.MODE_BASE, b"\x11" * 32, b"info", b"", b"")


def test_all_zero_dh_stays_validation_error() -> None:
    kem = DHKEM_X25519()
    sk, _pk = kem.generate_key_pair()
    zero_pk = kem.deserialize_public_key(b"\x00" * 32)
    with pytest.raises(ValidationError):
        kem.dh(sk, zero_pk)
    with pytest.raises(ValidationError):
        kem.decap(b"\x00" * 32, sk)
