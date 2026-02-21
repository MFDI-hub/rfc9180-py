from rfc9180.constants import AEADID, KDFID, HPKEMode
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.primitives.kem import (
    DHKEM_P256,
    DHKEM_P384,
    DHKEM_P521,
    DHKEM_X448,
    DHKEM_X25519,
)


def get_kem_class(kem_id: int):
    """Map KEM ID to KEM instance."""
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
    """Map KDF ID to KDF instance."""
    mapping = {
        0x0001: KDFID.HKDF_SHA256,
        0x0002: KDFID.HKDF_SHA384,
        0x0003: KDFID.HKDF_SHA512,
    }
    if kdf_id not in mapping:
        raise ValueError(f"Unsupported KDF ID: {kdf_id:04x}")
    return KDFBase(mapping[kdf_id])


def get_aead(aead_id: int):
    """Map AEAD ID to AEAD instance."""
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
    """Map mode integer to HPKEMode enum."""
    mapping = {
        0: HPKEMode.MODE_BASE,
        1: HPKEMode.MODE_PSK,
        2: HPKEMode.MODE_AUTH,
        3: HPKEMode.MODE_AUTH_PSK,
    }
    if mode not in mapping:
        raise ValueError(f"Unsupported mode: {mode}")
    return mapping[mode]
