import secrets
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import AEADID, KDFID
from rfc9180.exceptions import OpenError
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.primitives.kem import DHKEM_X25519
from rfc9180.setup import HPKESetup
from rfc9180.single_shot import HPKESingleShot


def build_env() -> tuple[DHKEM_X25519, HPKESetup, HPKESingleShot]:
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519()
    aead = AEADBase(AEADID.AES_128_GCM)
    setup = HPKESetup(kem, kdf, aead)
    return kem, setup, HPKESingleShot(setup)


@given(
    pkR=st.one_of(
        st.none(),
        st.integers(),
        st.binary(),
        st.text(),
        st.lists(st.integers()),
    )
)
@settings(max_examples=50)
def test_single_shot_rejects_non_key_pkR(pkR: Any) -> None:
    kem, _, single = build_env()
    _, good_pkR = kem.generate_key_pair()
    if isinstance(pkR, type(good_pkR)):
        pytest.skip("Generated a valid key; this test targets invalid types only")
    info = b"info"
    aad = b"aad"
    pt = b"msg"
    with pytest.raises((TypeError, ValueError, AttributeError)):
        single.seal_base(pkR, info, aad, pt)  # type: ignore[arg-type]


@given(
    info=st.binary(min_size=0, max_size=64),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=100)
def test_single_shot_base_roundtrip_fuzz(info: bytes, aad: bytes, pt: bytes) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    enc, ct = single.seal_base(pkR, info, aad, pt)
    out = single.open_base(enc, skR, info, aad, ct)
    assert out == pt


@given(
    info=st.binary(min_size=0, max_size=64),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=100)
def test_single_shot_auth_roundtrip_fuzz(info: bytes, aad: bytes, pt: bytes) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    skS, pkS = kem.generate_key_pair()
    enc, ct = single.seal_auth(pkR, info, aad, pt, skS)
    out = single.open_auth(enc, skR, info, aad, ct, pkS)
    assert out == pt


@given(
    info=st.binary(min_size=0, max_size=64),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
    psk=st.binary(min_size=32, max_size=64),
    psk_id=st.binary(min_size=1, max_size=32),
)
@settings(max_examples=100)
def test_single_shot_psk_roundtrip_fuzz(
    info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes
) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    enc, ct = single.seal_psk(pkR, info, aad, pt, psk, psk_id)
    out = single.open_psk(enc, skR, info, aad, ct, psk, psk_id)
    assert out == pt


@given(
    info=st.binary(min_size=0, max_size=64),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
    psk=st.binary(min_size=32, max_size=64),
    psk_id=st.binary(min_size=1, max_size=32),
)
@settings(max_examples=100)
def test_single_shot_auth_psk_roundtrip_fuzz(
    info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes
) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    skS, pkS = kem.generate_key_pair()
    enc, ct = single.seal_auth_psk(pkR, info, aad, pt, psk, psk_id, skS)
    out = single.open_auth_psk(enc, skR, info, aad, ct, psk, psk_id, pkS)
    assert out == pt


@given(
    info=st.binary(min_size=0, max_size=32),
    aad=st.binary(min_size=0, max_size=32),
    pt=st.binary(min_size=0, max_size=128),
)
@settings(max_examples=50)
def test_single_shot_base_modified_ciphertext_fails(
    info: bytes, aad: bytes, pt: bytes
) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    enc, ct = single.seal_base(pkR, info, aad, pt)
    mutated = bytearray(ct)
    if not mutated:
        pytest.skip("Ciphertext unexpectedly empty")
    idx = secrets.randbelow(len(mutated))
    mutated[idx] ^= 0x01
    with pytest.raises(OpenError):
        single.open_base(enc, skR, info, aad, bytes(mutated))


@given(
    info=st.binary(min_size=0, max_size=32),
    aad=st.binary(min_size=0, max_size=32),
    pt=st.binary(min_size=0, max_size=128),
    bad_aad=st.binary(min_size=0, max_size=32),
)
@settings(max_examples=50)
def test_single_shot_base_modified_aad_fails(
    info: bytes, aad: bytes, pt: bytes, bad_aad: bytes
) -> None:
    if aad == bad_aad:
        pytest.skip("Bad AAD equals original; nothing to test")
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    enc, ct = single.seal_base(pkR, info, aad, pt)
    with pytest.raises(OpenError):
        single.open_base(enc, skR, info, bad_aad, ct)


@given(
    info=st.binary(min_size=0, max_size=32),
    exporter_context=st.binary(min_size=0, max_size=32),
    L=st.integers(min_value=0, max_value=1024),
)
@settings(max_examples=50)
def test_single_shot_export_base_properties(
    info: bytes, exporter_context: bytes, L: int
) -> None:
    kem, _, single = build_env()
    skR, pkR = kem.generate_key_pair()
    enc, exported_sender = single.send_export_base(pkR, info, exporter_context, L)
    max_L = 255 * KDFBase(KDFID.HKDF_SHA256).Nh
    if L > max_L:
        with pytest.raises(ValueError):
            single.receive_export_base(enc, skR, info, exporter_context, L)
        return
    exported_recipient = single.receive_export_base(enc, skR, info, exporter_context, L)
    assert exported_sender == exported_recipient
    assert len(exported_sender) == L

