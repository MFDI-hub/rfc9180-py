from hpke import append_header, parse_header
from hpke.constants import KEMID, KDFID, AEADID, HPKEMode
from hpke import HPKE


def test_header_round_trip():
    hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)
    skR, pkR = hpke.kem.generate_key_pair()
    info = b"hdr"
    aad = b""
    pt = b"payload"

    enc, ct = hpke.seal_base(pkR, info, aad, pt)
    msg = append_header(enc, ct, int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id), int(HPKEMode.MODE_BASE))

    kem_id2, kdf_id2, aead_id2, mode2, enc2, ct2 = parse_header(msg, enc_len=hpke.kem.Nenc)
    assert kem_id2 == int(hpke.kem_id)
    assert kdf_id2 == int(hpke.kdf_id)
    assert aead_id2 == int(hpke.aead_id)
    assert mode2 == int(HPKEMode.MODE_BASE)

    out = hpke.open_base(enc2, skR, info, aad, ct2)
    assert out == pt


def test_header_errors():
    # Too short
    try:
        parse_header(b"HPK", enc_len=32)
        assert False, "Expected error for short header"
    except ValueError:
        pass

    # Bad magic
    try:
        parse_header(b"NOPE" + b"\x00" * (2 + 2 + 2 + 1 + 10), enc_len=16)
        assert False, "Expected error for bad magic"
    except ValueError:
        pass


