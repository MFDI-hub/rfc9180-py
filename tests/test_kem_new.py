from rfc9180.primitives.kem import DHKEM_P384, DHKEM_P521, DHKEM_X448


def test_kem_p384_flow():
    kem = DHKEM_P384()
    sk, pk = kem.generate_key_pair()

    # Check sizes
    pk_bytes = kem.serialize_public_key(pk)
    sk_bytes = kem.serialize_private_key(sk)
    assert len(pk_bytes) == kem.Npk
    assert len(sk_bytes) == kem.Nsk

    # Encap/Decap
    shared_s, enc = kem.encap(pk)
    shared_r = kem.decap(enc, sk)
    assert shared_s == shared_r
    assert len(shared_s) == kem.Nsecret


def test_kem_p521_flow():
    kem = DHKEM_P521()
    sk, pk = kem.generate_key_pair()

    # Check sizes
    pk_bytes = kem.serialize_public_key(pk)
    sk_bytes = kem.serialize_private_key(sk)
    assert len(pk_bytes) == kem.Npk
    assert len(sk_bytes) == kem.Nsk

    # Encap/Decap
    shared_s, enc = kem.encap(pk)
    shared_r = kem.decap(enc, sk)
    assert shared_s == shared_r
    assert len(shared_s) == kem.Nsecret


def test_kem_x448_flow():
    kem = DHKEM_X448()
    sk, pk = kem.generate_key_pair()

    # Check sizes
    pk_bytes = kem.serialize_public_key(pk)
    sk_bytes = kem.serialize_private_key(sk)
    assert len(pk_bytes) == kem.Npk
    assert len(sk_bytes) == kem.Nsk

    # Encap/Decap
    shared_s, enc = kem.encap(pk)
    shared_r = kem.decap(enc, sk)
    assert shared_s == shared_r
    assert len(shared_s) == kem.Nsecret


def test_kem_x448_deterministic():
    kem = DHKEM_X448()
    ikm = b"\x01" * kem.Nsk
    sk1, pk1 = kem.derive_key_pair(ikm)
    sk2, pk2 = kem.derive_key_pair(ikm)
    assert kem.serialize_public_key(pk1) == kem.serialize_public_key(pk2)


