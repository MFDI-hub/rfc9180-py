"""
Test suite for RFC 9180 HPKE test vectors.

This test suite loads and validates test vectors from the official RFC 9180
test vectors repository:
https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/main/test-vectors.json
"""

import json
import os

import pytest

from hpke.constants import AEADID, KDFID, HPKEMode
from hpke.primitives.aead import AEADBase
from hpke.primitives.kdf import KDFBase
from hpke.primitives.kem import (
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X448,
    DHKEM_X25519,
)
from hpke.setup import HPKESetup


def load_test_vectors():
    """Load test vectors from test_vectos.json"""
    vector_path = os.path.join(os.path.dirname(__file__), "test_vectos.json")
    if not os.path.exists(vector_path):
        pytest.skip(f"Test vector file not found: {vector_path}")
    with open(vector_path, encoding="utf-8") as f:
        return json.load(f)


def get_kem_class(kem_id: int):
    """Map KEM ID to KEM class"""
    mapping = {
        0x0010: DHKEM_P256,
        0x0011: DHKEM_P384,
        0x0012: DHKEM_P521,
        0x0020: DHKEM_X25519,
        0x0021: DHKEM_X448,
    }
    if kem_id not in mapping:
        raise ValueError(f"Unsupported KEM ID: {kem_id:04x}")
    return mapping[kem_id]()


def get_kdf(kdf_id: int):
    """Map KDF ID to KDF instance"""
    mapping = {
        0x0001: KDFID.HKDF_SHA256,
        0x0002: KDFID.HKDF_SHA384,
        0x0003: KDFID.HKDF_SHA512,
    }
    if kdf_id not in mapping:
        raise ValueError(f"Unsupported KDF ID: {kdf_id:04x}")
    return KDFBase(mapping[kdf_id])


def get_aead(aead_id: int):
    """Map AEAD ID to AEAD instance"""
    mapping = {
        0x0001: AEADID.AES_128_GCM,
        0x0002: AEADID.AES_256_GCM,
        0x0003: AEADID.CHACHA20_POLY1305,
        0xFFFF: AEADID.EXPORT_ONLY,
    }
    if aead_id not in mapping:
        raise ValueError(f"Unsupported AEAD ID: {aead_id:04x}")
    return AEADBase(mapping[aead_id])


def get_mode(mode: int):
    """Map mode integer to HPKEMode enum"""
    mapping = {
        0: HPKEMode.MODE_BASE,
        1: HPKEMode.MODE_PSK,
        2: HPKEMode.MODE_AUTH,
        3: HPKEMode.MODE_AUTH_PSK,
    }
    if mode not in mapping:
        raise ValueError(f"Unsupported mode: {mode}")
    return mapping[mode]


@pytest.fixture(scope="module")
def test_vectors():
    """Load test vectors once for all tests"""
    return load_test_vectors()


@pytest.mark.parametrize("vector_idx", range(len(load_test_vectors())))
def test_hpke_vector(vector_idx, test_vectors):
    """
    Test a single HPKE test vector.

    This test:
    1. Sets up the HPKE configuration from the vector
    2. Derives key pairs from IKM values
    3. Tests encryption/decryption (if encryptions are present)
    4. Tests export functionality (if exports are present)
    """
    vec = test_vectors[vector_idx]

    # Extract configuration
    kem_id = vec["kem_id"]
    kdf_id = vec["kdf_id"]
    aead_id = vec["aead_id"]
    mode = get_mode(vec["mode"])

    # Create HPKE components
    kem = get_kem_class(kem_id)
    kdf = get_kdf(kdf_id)
    aead = get_aead(aead_id)
    setup = HPKESetup(kem, kdf, aead)

    # Derive key pairs from IKM
    ikmR = bytes.fromhex(vec["ikmR"])
    skR, pkR = kem.derive_key_pair(ikmR)

    # Verify recipient public key matches expected
    pkR_expected = bytes.fromhex(vec["pkRm"])
    assert kem.serialize_public_key(pkR) == pkR_expected, \
        f"Recipient public key mismatch in vector {vector_idx}"

    # Verify recipient private key serialization matches expected
    skR_expected = bytes.fromhex(vec["skRm"])
    assert kem.serialize_private_key(skR) == skR_expected, \
        f"Recipient private key mismatch in vector {vector_idx}"

    # Derive ephemeral key pair if present
    ikmE = bytes.fromhex(vec["ikmE"])
    skE, pkE = kem.derive_key_pair(ikmE)

    # Verify ephemeral public key matches expected
    pkE_expected = bytes.fromhex(vec["pkEm"])
    assert kem.serialize_public_key(pkE) == pkE_expected, \
        f"Ephemeral public key mismatch in vector {vector_idx}"

    # Verify ephemeral private key serialization matches expected
    skE_expected = bytes.fromhex(vec["skEm"])
    assert kem.serialize_private_key(skE) == skE_expected, \
        f"Ephemeral private key mismatch in vector {vector_idx}"

    # Verify enc value matches expected
    enc_expected = bytes.fromhex(vec["enc"])
    assert kem.serialize_public_key(pkE) == enc_expected, \
        f"Enc value mismatch in vector {vector_idx}"

    # Derive sender key pair for AUTH modes
    skS = None
    pkS = None
    if mode in (HPKEMode.MODE_AUTH, HPKEMode.MODE_AUTH_PSK):
        ikmS = bytes.fromhex(vec["ikmS"])
        skS, pkS = kem.derive_key_pair(ikmS)

        # Verify sender public key matches expected
        pkS_expected = bytes.fromhex(vec["pkSm"])
        assert kem.serialize_public_key(pkS) == pkS_expected, \
            f"Sender public key mismatch in vector {vector_idx}"

        # Verify sender private key serialization matches expected
        skS_expected = bytes.fromhex(vec["skSm"])
        assert kem.serialize_private_key(skS) == skS_expected, \
            f"Sender private key mismatch in vector {vector_idx}"

    # Extract PSK if present
    psk = bytes.fromhex(vec.get("psk", "")) if "psk" in vec else b""
    psk_id = bytes.fromhex(vec.get("psk_id", "")) if "psk_id" in vec else b""

    # Extract info
    info = bytes.fromhex(vec["info"])

    # Compute shared secret using deterministic keys
    # For deterministic test vectors, we use the provided ephemeral key
    enc = enc_expected
    if mode == HPKEMode.MODE_BASE:
        shared_secret = kem.decap(enc, skR)
    elif mode == HPKEMode.MODE_PSK:
        shared_secret = kem.decap(enc, skR)
    elif mode == HPKEMode.MODE_AUTH:
        shared_secret = kem.auth_decap(enc, skR, pkS)
    elif mode == HPKEMode.MODE_AUTH_PSK:
        shared_secret = kem.auth_decap(enc, skR, pkS)

    # Verify shared secret matches expected
    shared_secret_expected = bytes.fromhex(vec["shared_secret"])
    assert shared_secret == shared_secret_expected, \
        f"Shared secret mismatch in vector {vector_idx}"

    # Setup contexts to verify intermediate key schedule values
    ctx_sender = setup.key_schedule(
        'S', mode, shared_secret, info, psk=psk, psk_id=psk_id
    )
    ctx_recipient = setup.key_schedule(
        'R', mode, shared_secret, info, psk=psk, psk_id=psk_id
    )

    # Verify intermediate key schedule values if present
    if "key" in vec and vec["key"]:
        key_expected = bytes.fromhex(vec["key"])
        assert ctx_sender.key == key_expected, \
            f"Key mismatch in vector {vector_idx}"
        assert ctx_recipient.key == key_expected, \
            f"Key mismatch in recipient context for vector {vector_idx}"

    if "base_nonce" in vec and vec["base_nonce"]:
        base_nonce_expected = bytes.fromhex(vec["base_nonce"])
        assert ctx_sender.base_nonce == base_nonce_expected, \
            f"Base nonce mismatch in vector {vector_idx}"
        assert ctx_recipient.base_nonce == base_nonce_expected, \
            f"Base nonce mismatch in recipient context for vector {vector_idx}"

    if "exporter_secret" in vec and vec["exporter_secret"]:
        exporter_secret_expected = bytes.fromhex(vec["exporter_secret"])
        assert ctx_sender.exporter_secret == exporter_secret_expected, \
            f"Exporter secret mismatch in vector {vector_idx}"
        assert ctx_recipient.exporter_secret == exporter_secret_expected, \
            f"Exporter secret mismatch in recipient context for vector {vector_idx}"

    # Test encryption/decryption if encryptions are present
    if "encryptions" in vec and len(vec["encryptions"]) > 0:
        # Test encryption: create fresh sender context and encrypt each message
        ctx_sender_enc = setup.key_schedule(
            'S', mode, shared_secret, info, psk=psk, psk_id=psk_id
        )
        for idx, enc_data in enumerate(vec["encryptions"]):
            aad = bytes.fromhex(enc_data["aad"])
            ct_expected = bytes.fromhex(enc_data["ct"])
            pt_expected = bytes.fromhex(enc_data["pt"])

            # Encrypt with sender context and verify ciphertext matches
            ct_actual = ctx_sender_enc.seal(aad, pt_expected)
            assert ct_actual == ct_expected, \
                f"Ciphertext mismatch in vector {vector_idx}, encryption {idx} (aad: {enc_data.get('aad', 'unknown')})"

        # Test decryption: create fresh recipient context and decrypt each message
        ctx_recipient_dec = setup.key_schedule(
            'R', mode, shared_secret, info, psk=psk, psk_id=psk_id
        )
        for idx, enc_data in enumerate(vec["encryptions"]):
            aad = bytes.fromhex(enc_data["aad"])
            ct_expected = bytes.fromhex(enc_data["ct"])
            pt_expected = bytes.fromhex(enc_data["pt"])

            # Decrypt with recipient context and verify plaintext matches
            pt_actual = ctx_recipient_dec.open(aad, ct_expected)
            assert pt_actual == pt_expected, \
                f"Plaintext mismatch in vector {vector_idx}, encryption {idx} (aad: {enc_data.get('aad', 'unknown')})"

    # Test export functionality if exports are present
    if "exports" in vec and len(vec["exports"]) > 0:
        # Reuse contexts already created above (they're the same)

        # Test each export
        for export_data in vec["exports"]:
            exporter_context = bytes.fromhex(export_data["exporter_context"])
            L = export_data["L"]
            exported_value_expected = bytes.fromhex(export_data["exported_value"])

            # Export from both contexts and verify they match
            exported_sender = ctx_sender.export(exporter_context, L)
            exported_recipient = ctx_recipient.export(exporter_context, L)

            assert exported_sender == exported_recipient, \
                f"Export mismatch between sender and recipient in vector {vector_idx}"

            assert exported_sender == exported_value_expected, \
                f"Export value mismatch in vector {vector_idx}, context {export_data.get('exporter_context', '')}"

