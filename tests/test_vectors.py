import json
import os

import pytest

from rfc9180.constants import AEADID, KDFID
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.primitives.kem import DHKEM_P256, DHKEM_X25519
from rfc9180.setup import HPKESetup


def load_vector(path: str):
    if not os.path.exists(path):
        pytest.skip(f"Vector file not found: {path}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_vector_x25519_aes128gcm_base_decrypt():
    """
    Placeholder harness: loads a RFC 9180-style JSON vector and verifies decryption.
    Skips if the vector file is missing.
    """
    vector_path = os.path.join("vectors", "dhkem_x25519_aes128gcm_base.json")
    vec = load_vector(vector_path)

    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = DHKEM_X25519()
    aead = AEADBase(AEADID.AES_128_GCM)
    setup = HPKESetup(kem, kdf, aead)

    skR = kem.deserialize_private_key(bytes.fromhex(vec['skRm']))
    info = bytes.fromhex(vec['info'])

    enc = bytes.fromhex(vec['enc'])
    ctx_r = setup.setup_base_recipient(enc, skR, info)

    for msg in vec.get('encryptions', []):
        aad = bytes.fromhex(msg['aad'])
        ct = bytes.fromhex(msg['ct'])
        pt_expected = bytes.fromhex(msg['pt'])
        pt = ctx_r.open(aad, ct)
        assert pt == pt_expected


@pytest.mark.parametrize(
    "kem_ctor,aead_id,filename",
    [
        (DHKEM_P256, AEADID.AES_128_GCM, "dhkem_p256_aes128gcm_base.json"),
        (DHKEM_P256, AEADID.AES_256_GCM, "dhkem_p256_aes256gcm_base.json"),
        (DHKEM_P256, AEADID.CHACHA20_POLY1305, "dhkem_p256_chacha20poly1305_base.json"),
    ],
)
def test_vector_optional_matrix_base_decrypt(kem_ctor, aead_id, filename):
    vector_path = os.path.join("vectors", filename)
    vec = load_vector(vector_path)

    kdf = KDFBase(KDFID.HKDF_SHA256)
    kem = kem_ctor()
    aead = AEADBase(aead_id)
    setup = HPKESetup(kem, kdf, aead)

    skR = kem.deserialize_private_key(bytes.fromhex(vec['skRm']))
    info = bytes.fromhex(vec['info'])

    enc = bytes.fromhex(vec['enc'])
    ctx_r = setup.setup_base_recipient(enc, skR, info)

    for msg in vec.get('encryptions', []):
        aad = bytes.fromhex(msg['aad'])
        ct = bytes.fromhex(msg['ct'])
        pt_expected = bytes.fromhex(msg['pt'])
        pt = ctx_r.open(aad, ct)
        assert pt == pt_expected


