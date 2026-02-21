import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization

from rfc9180 import KEMKey, create_hpke
from rfc9180.constants import AEADID, KDFID, KEMID


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize(
    ("kem_id", "kdf_id", "crv_name"),
    [
        (KEMID.DHKEM_P256_HKDF_SHA256, KDFID.HKDF_SHA256, "P-256"),
        (KEMID.DHKEM_P384_HKDF_SHA384, KDFID.HKDF_SHA384, "P-384"),
        (KEMID.DHKEM_P521_HKDF_SHA512, KDFID.HKDF_SHA512, "P-521"),
    ],
)
def test_jwk_ec_roundtrip(kem_id: KEMID, kdf_id: KDFID, crv_name: str) -> None:
    hpke = create_hpke(kem_id=kem_id, kdf_id=kdf_id, aead_id=AEADID.AES_128_GCM)
    sk, pk = hpke.generate_key_pair()
    public = pk.public_numbers()
    scalar_len = hpke.kem.Nsk

    x = public.x.to_bytes(scalar_len, "big")
    y = public.y.to_bytes(scalar_len, "big")
    d = sk.private_numbers().private_value.to_bytes(scalar_len, "big")

    jwk_pub = {"kty": "EC", "crv": crv_name, "x": _b64u(x), "y": _b64u(y)}
    jwk_priv = {"kty": "EC", "crv": crv_name, "x": _b64u(x), "y": _b64u(y), "d": _b64u(d)}

    pub_key = KEMKey.from_jwk(jwk_pub)
    priv_key = KEMKey.from_jwk(jwk_priv)

    assert hpke.serialize_public_key(pub_key) == hpke.serialize_public_key(pk)
    assert hpke.serialize_private_key(priv_key) == hpke.serialize_private_key(sk)


@pytest.mark.parametrize(
    ("kem_id", "kdf_id", "crv_name"),
    [
        (KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, "X25519"),
        (KEMID.DHKEM_X448_HKDF_SHA512, KDFID.HKDF_SHA512, "X448"),
    ],
)
def test_jwk_okp_roundtrip(kem_id: KEMID, kdf_id: KDFID, crv_name: str) -> None:
    hpke = create_hpke(kem_id=kem_id, kdf_id=kdf_id, aead_id=AEADID.AES_128_GCM)
    sk, pk = hpke.generate_key_pair()
    pk_bytes = hpke.serialize_public_key(pk)
    sk_bytes = hpke.serialize_private_key(sk)

    jwk_pub = {"kty": "OKP", "crv": crv_name, "x": _b64u(pk_bytes)}
    jwk_priv = {"kty": "OKP", "crv": crv_name, "x": _b64u(pk_bytes), "d": _b64u(sk_bytes)}

    pub_key = KEMKey.from_jwk(json.dumps(jwk_pub))
    priv_key = KEMKey.from_jwk(jwk_priv)

    assert hpke.serialize_public_key(pub_key) == pk_bytes
    assert hpke.serialize_private_key(priv_key) == sk_bytes


def test_jwk_invalid_inputs() -> None:
    with pytest.raises(ValueError):
        KEMKey.from_jwk({"kty": "RSA"})

    with pytest.raises(ValueError):
        KEMKey.from_jwk({"kty": "EC", "crv": "P-256", "x": "AA"})

    with pytest.raises(ValueError):
        KEMKey.from_jwk({"kty": "OKP", "crv": "X25519", "x": _b64u(b"\x00" * 31)})


def test_pem_loading_public_private() -> None:
    hpke = create_hpke()
    sk, pk = hpke.generate_key_pair()

    pub_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_key = KEMKey.from_pem(pub_pem)
    priv_key = KEMKey.from_pem(priv_pem.decode("utf-8"))

    assert hpke.serialize_public_key(pub_key) == hpke.serialize_public_key(pk)
    assert hpke.serialize_private_key(priv_key) == hpke.serialize_private_key(sk)


def test_jwk_integration_seal_open_base_x25519() -> None:
    hpke = create_hpke()
    sk_r, pk_r = hpke.generate_key_pair()

    pk_r_jwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": _b64u(hpke.serialize_public_key(pk_r)),
    }
    sk_r_jwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": _b64u(hpke.serialize_public_key(pk_r)),
        "d": _b64u(hpke.serialize_private_key(sk_r)),
    }
    pkr = KEMKey.from_jwk(pk_r_jwk)
    skr = KEMKey.from_jwk(sk_r_jwk)
    info = b"jwk-integration"
    aad = b"aad"
    pt = b"hello jwk"

    enc, ct = hpke.seal_base(pkr, info, aad, pt)
    out = hpke.open_base(enc, skr, info, aad, ct)
    assert out == pt
