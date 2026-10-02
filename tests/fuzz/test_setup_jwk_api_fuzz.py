import base64

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180 import KEMKey, create_hpke
from rfc9180.constants import AEADID, KDFID, KEMID
from rfc9180.exceptions import OpenError


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@given(
    kem_id=st.sampled_from(list(KEMID)),
    kdf_id=st.sampled_from(list(KDFID)),
    aead_id=st.sampled_from(list(AEADID)),
)
@settings(max_examples=50)
def test_setup_suite_selection_roundtrip(kem_id: KEMID, kdf_id: KDFID, aead_id: AEADID) -> None:
    hpke = create_hpke(kem_id=kem_id, kdf_id=kdf_id, aead_id=aead_id)
    skR, pkR = hpke.generate_key_pair()
    info = b"fuzz-info"
    aad = b"aad"
    pt = b"payload"
    enc, ct = hpke.seal_base(pkR, info, aad, pt)
    out = hpke.open_base(enc, skR, info, aad, ct)
    assert out == pt


@given(
    kem_id=st.sampled_from(list(KEMID)),
    kdf_id=st.sampled_from(list(KDFID)),
)
@settings(max_examples=50)
def test_jwk_parsing_with_randomized_structures(kem_id: KEMID, kdf_id: KDFID) -> None:
    hpke = create_hpke(kem_id=kem_id, kdf_id=kdf_id, aead_id=AEADID.AES_128_GCM)
    sk, pk = hpke.generate_key_pair()
    pk_bytes = hpke.serialize_public_key(pk)
    sk_bytes = hpke.serialize_private_key(sk)

    if kem_id in (
        KEMID.DHKEM_P256_HKDF_SHA256,
        KEMID.DHKEM_P384_HKDF_SHA384,
        KEMID.DHKEM_P521_HKDF_SHA512,
    ):
        crv_name = {
            KEMID.DHKEM_P256_HKDF_SHA256: "P-256",
            KEMID.DHKEM_P384_HKDF_SHA384: "P-384",
            KEMID.DHKEM_P521_HKDF_SHA512: "P-521",
        }[kem_id]
        scalar_len = hpke.kem.Nsk
        public = pk.public_numbers()
        x = public.x.to_bytes(scalar_len, "big")
        y = public.y.to_bytes(scalar_len, "big")
        jwk_pub = {"kty": "EC", "crv": crv_name, "x": b64u(x), "y": b64u(y)}
        jwk_priv = {"kty": "EC", "crv": crv_name, "x": b64u(x), "y": b64u(y), "d": b64u(sk_bytes)}
    else:
        crv_name = "X25519" if kem_id == KEMID.DHKEM_X25519_HKDF_SHA256 else "X448"
        jwk_pub = {"kty": "OKP", "crv": crv_name, "x": b64u(pk_bytes)}
        jwk_priv = {"kty": "OKP", "crv": crv_name, "x": b64u(pk_bytes), "d": b64u(sk_bytes)}

    pub_key = KEMKey.from_jwk(jwk_pub)
    priv_key = KEMKey.from_jwk(jwk_priv)
    assert hpke.serialize_public_key(pub_key) == pk_bytes
    assert hpke.serialize_private_key(priv_key) == sk_bytes


@given(
    kem_id=st.sampled_from(list(KEMID)),
    kdf_id=st.sampled_from(list(KDFID)),
    aad=st.binary(min_size=0, max_size=64),
    pt=st.binary(min_size=0, max_size=256),
)
@settings(max_examples=50)
def test_end_to_end_pipeline_with_corruption(
    kem_id: KEMID, kdf_id: KDFID, aad: bytes, pt: bytes
) -> None:
    hpke = create_hpke(kem_id=kem_id, kdf_id=kdf_id, aead_id=AEADID.AES_128_GCM)
    skR, pkR = hpke.generate_key_pair()
    info = b"end-to-end"
    enc, ct = hpke.seal_base(pkR, info, aad, pt)
    out = hpke.open_base(enc, skR, info, aad, ct)
    assert out == pt

    corrupted_ct = bytearray(ct)
    if corrupted_ct:
        corrupted_ct[0] ^= 0x01
        with pytest.raises(OpenError):
            hpke.open_base(enc, skR, info, aad, bytes(corrupted_ct))

