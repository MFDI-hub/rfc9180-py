from rfc9180.constants import AEADID, KDFID
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.primitives.kem import DHKEM_X25519
from rfc9180.setup import HPKESetup


def test_setup_base_roundtrip():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519()
    aead = AEADBase(AEADID.AES_128_GCM)
    setup = HPKESetup(kem, kdf, aead)
    skR, pkR = kem.generate_key_pair()
    info = b"test"
    enc, sender = setup.setup_base_sender(pkR, info)
    recipient = setup.setup_base_recipient(enc, skR, info)
    aad = b""
    pt = b"hello setup"
    ct = sender.seal(aad, pt)
    assert recipient.open(aad, ct) == pt


