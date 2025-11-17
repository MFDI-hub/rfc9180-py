import pytest

from hpke.primitives.kdf import KDFBase
from hpke.primitives.kem import DHKEM_X25519
from hpke.constants import KDFID


def test_key_generation_x25519():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    sk, pk = kem.generate_key_pair()
    assert sk is not None and pk is not None
    pk_bytes = kem.serialize_public_key(pk)
    assert len(pk_bytes) == kem.Npk


def test_derive_key_pair_x25519_deterministic():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    ikm = b"X25519 deterministic seed........"[:kem.Nsk]
    sk1, pk1 = kem.derive_key_pair(ikm)
    sk2, pk2 = kem.derive_key_pair(ikm)
    assert kem.serialize_public_key(pk1) == kem.serialize_public_key(pk2)
    assert kem.serialize_private_key(sk1) == kem.serialize_private_key(sk2)


def test_encap_decap_x25519():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    skR, pkR = kem.generate_key_pair()
    ss_s, enc = kem.encap(pkR)
    ss_r = kem.decap(enc, skR)
    assert ss_s == ss_r
    assert len(ss_s) == kem.Nsecret


def test_auth_encap_decap_x25519():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    skR, pkR = kem.generate_key_pair()
    skS, pkS = kem.generate_key_pair()
    ss_s, enc = kem.auth_encap(pkR, skS)
    ss_r = kem.auth_decap(enc, skR, pkS)
    assert ss_s == ss_r


