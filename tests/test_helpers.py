from rfc9180 import HPKE, append_header, parse_header
from rfc9180.constants import AEADID, KDFID, KEMID, HPKEMode


def test_header_round_trip():
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    skR, pkR = hpke.kem.generate_key_pair()
    info = b"hdr"
    aad = b""
    pt = b"payload"

    enc, ct = hpke.seal_base(pkR, info, aad, pt)
    msg = append_header(
        enc, ct, int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id), int(HPKEMode.MODE_BASE)
    )

    kem_id2, kdf_id2, aead_id2, mode2, enc2, ct2 = parse_header(msg, enc_len=hpke.kem.Nenc)
    assert kem_id2 == int(hpke.kem_id)
    assert kdf_id2 == int(hpke.kdf_id)
    assert aead_id2 == int(hpke.aead_id)
    assert mode2 == int(HPKEMode.MODE_BASE)

    out = hpke.open_base(enc2, skR, info, aad, ct2)
    assert out == pt


def test_header_rejects_enc_len_that_disagrees_with_kem_id():
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    enc = b"\x02" * hpke.kem.Nenc
    ct = b"\x03" * hpke.aead.Nt
    msg = append_header(
        enc, ct, int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id), int(HPKEMode.MODE_BASE)
    )
    try:
        parse_header(msg, enc_len=hpke.kem.Nenc - 1)
        raise AssertionError("Expected enc_len mismatch to fail")
    except ValueError:
        pass


def test_header_rejects_ciphertext_shorter_than_tag():
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    enc = b"\x02" * hpke.kem.Nenc
    msg = append_header(
        enc,
        b"\x03" * (hpke.aead.Nt - 1),
        int(hpke.kem_id),
        int(hpke.kdf_id),
        int(hpke.aead_id),
        int(HPKEMode.MODE_BASE),
    )
    try:
        parse_header(msg, enc_len=hpke.kem.Nenc)
        raise AssertionError("Expected short ciphertext to fail")
    except ValueError:
        pass


def test_header_rejects_unknown_kdf_and_mode():
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    enc = b"\x02" * hpke.kem.Nenc
    ct = b"\x03" * hpke.aead.Nt
    bad_kdf = append_header(
        enc, ct, int(hpke.kem_id), 0x9999, int(hpke.aead_id), int(HPKEMode.MODE_BASE)
    )
    try:
        parse_header(bad_kdf, enc_len=hpke.kem.Nenc)
        raise AssertionError("Expected unknown kdf_id to fail")
    except ValueError as exc:
        assert "KDF" in str(exc)

    bad_mode = append_header(enc, ct, int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id), 0x07)
    try:
        parse_header(bad_mode, enc_len=hpke.kem.Nenc)
        raise AssertionError("Expected unknown mode to fail")
    except ValueError as exc:
        assert "mode" in str(exc)


def test_header_errors():
    # Too short
    try:
        parse_header(b"HPK", enc_len=32)
        raise AssertionError("Expected error for short header")
    except ValueError:
        pass

    # Bad magic
    try:
        parse_header(b"NOPE" + b"\x00" * (2 + 2 + 2 + 1 + 10), enc_len=16)
        raise AssertionError("Expected error for bad magic")
    except ValueError:
        pass
