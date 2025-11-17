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


def test_multi_message_roundtrip_base():
    kem, setup = build_env()
    skR, pkR = kem.generate_key_pair()
    info = b"multi"
    enc, sender = setup.setup_base_sender(pkR, info)
    recipient = setup.setup_base_recipient(enc, skR, info)
    aad = b""
    pts = [b"m1", b"m2", b"m3"]
    cts = [sender.seal(aad, pt) for pt in pts]
    outs = [recipient.open(aad, ct) for ct in cts]
    assert outs == pts


def test_exporter_values_match():
    kem, setup = build_env()
    skR, pkR = kem.generate_key_pair()
    info = b"export"
    enc, sender = setup.setup_base_sender(pkR, info)
    recipient = setup.setup_base_recipient(enc, skR, info)
    exporter_context = b"label"
    L = 32
    assert sender.export(exporter_context, L) == recipient.export(exporter_context, L)


def test_export_only_flow():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519(kdf)
    aead = AEADBase(AEADID.EXPORT_ONLY)
    setup = HPKESetup(kem, kdf, aead)
    single = HPKESingleShot(setup)
    skR, pkR = kem.generate_key_pair()
    info = b"export-only"
    exporter_context = b"context"
    L = 32
    enc, exported_s = single.send_export_base(pkR, info, exporter_context, L)
    exported_r = single.receive_export_base(enc, skR, info, exporter_context, L)
    assert exported_s == exported_r and len(exported_s) == L


