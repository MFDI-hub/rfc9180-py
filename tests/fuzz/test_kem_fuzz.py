from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import KEMID
from rfc9180.exceptions import DecapError, DeriveKeyPairError, DeserializeError, EncapError, ValidationError
from rfc9180.primitives.kem import (
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X25519,
    DHKEM_X448,
    KEMBase,
)


def kem_strategies() -> st.SearchStrategy[KEMBase]:
    return st.sampled_from(
        [
            DHKEM_X25519(),
            DHKEM_X448(),
            DHKEM_P256(),
            DHKEM_P384(),
            DHKEM_P521(),
        ]
    )


@given(kem=kem_strategies())
@settings(max_examples=50)
def test_kem_generate_key_pair_basic_properties(kem: KEMBase) -> None:
    sk, pk = kem.generate_key_pair()
    pk_bytes = kem.serialize_public_key(pk)
    sk_bytes = kem.serialize_private_key(sk)
    assert len(pk_bytes) == kem.Npk
    assert len(sk_bytes) == kem.Nsk


@given(kem=kem_strategies(), ikm=st.binary(min_size=0, max_size=128))
@settings(max_examples=100)
def test_kem_derive_key_pair_length_and_determinism(kem: KEMBase, ikm: bytes) -> None:
    if len(ikm) < kem.Nsk:
        with pytest.raises(ValueError):
            kem.derive_key_pair(ikm)
        return
    sk1, pk1 = kem.derive_key_pair(ikm)
    sk2, pk2 = kem.derive_key_pair(ikm)
    assert kem.serialize_public_key(pk1) == kem.serialize_public_key(pk2)
    assert kem.serialize_private_key(sk1) == kem.serialize_private_key(sk2)


@given(kem=kem_strategies(), enc=st.binary(min_size=0, max_size=256))
@settings(max_examples=100)
def test_kem_decap_rejects_malformed_enc(kem: KEMBase, enc: bytes) -> None:
    skR, pkR = kem.generate_key_pair()
    _, good_enc = kem.encap(pkR)
    if len(enc) == kem.Nenc and enc != good_enc:
        with pytest.raises(DecapError):
            kem.decap(enc, skR)
    elif len(enc) != kem.Nenc:
        with pytest.raises((DecapError, DeserializeError)):
            kem.decap(enc, skR)


@given(kem=kem_strategies())
@settings(max_examples=50)
def test_kem_encap_decap_roundtrip(kem: KEMBase) -> None:
    skR, pkR = kem.generate_key_pair()
    ss_s, enc = kem.encap(pkR)
    ss_r = kem.decap(enc, skR)
    assert ss_s == ss_r
    assert len(ss_s) == kem.Nsecret


@given(kem=kem_strategies())
@settings(max_examples=50)
def test_kem_auth_encap_decap_roundtrip(kem: KEMBase) -> None:
    skR, pkR = kem.generate_key_pair()
    skS, pkS = kem.generate_key_pair()
    ss_s, enc = kem.auth_encap(pkR, skS)
    ss_r = kem.auth_decap(enc, skR, pkS)
    assert ss_s == ss_r


@given(kem=kem_strategies(), bad_pk=st.binary(min_size=0, max_size=256))
@settings(max_examples=50)
def test_kem_encap_rejects_malformed_pk(kem: KEMBase, bad_pk: bytes) -> None:
    if len(bad_pk) != kem.Npk:
        with pytest.raises((EncapError, DeserializeError)):
            kem.encap(kem.deserialize_public_key(bad_pk))  # type: ignore[arg-type]


@given(kem=kem_strategies(), bad_sk=st.binary(min_size=0, max_size=256))
@settings(max_examples=50)
def test_kem_dh_rejects_invalid_scalar(kem: KEMBase, bad_sk: bytes) -> None:
    _, pk = kem.generate_key_pair()
    if len(bad_sk) != kem.Nsk:
        with pytest.raises((ValidationError, DeserializeError, TypeError)):
            sk = kem.deserialize_private_key(bad_sk)  # type: ignore[assignment]
            kem.dh(sk, pk)  # pragma: no cover


@given(kem=kem_strategies(), raw=st.integers(min_value=0, max_value=0xFFFF))
@settings(max_examples=50)
def test_kemid_enum_mapping_bounds(kem: KEMBase, raw: int) -> None:
    try:
        kid = KEMID(raw)
    except ValueError:
        return
    assert kid in KEMID

