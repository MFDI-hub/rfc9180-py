import secrets

from hpke.primitives.kdf import KDFBase
from hpke.primitives.kem import DHKEM_X25519
from hpke.primitives.aead import AEADBase
from hpke.setup import HPKESetup
from hpke.single_shot import HPKESingleShot
from hpke.constants import KDFID, AEADID


def build_env():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    aead = AEADBase(AEADID.AES_128_GCM)
    setup = HPKESetup(kem, kdf, aead)
    return kem, setup


def test_single_shot_base():
    kem, setup = build_env()
    single = HPKESingleShot(setup)
    skR, pkR = kem.generate_key_pair()
    info = b"info"
    aad = b""
    pt = b"secret"
    enc, ct = single.seal_base(pkR, info, aad, pt)
    out = single.open_base(enc, skR, info, aad, ct)
    assert out == pt


def test_single_shot_auth():
    kem, setup = build_env()
    single = HPKESingleShot(setup)
    skR, pkR = kem.generate_key_pair()
    skS, pkS = kem.generate_key_pair()
    info = b"auth"
    aad = b""
    pt = b"auth msg"
    enc, ct = single.seal_auth(pkR, info, aad, pt, skS)
    out = single.open_auth(enc, skR, info, aad, ct, pkS)
    assert out == pt


def test_single_shot_psk():
    kem, setup = build_env()
    single = HPKESingleShot(setup)
    skR, pkR = kem.generate_key_pair()
    info = b"psk"
    aad = b""
    pt = b"psk msg"
    psk = secrets.token_bytes(32)
    psk_id = b"psk-id"
    enc, ct = single.seal_psk(pkR, info, aad, pt, psk, psk_id)
    out = single.open_psk(enc, skR, info, aad, ct, psk, psk_id)
    assert out == pt


