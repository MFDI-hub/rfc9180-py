"""
hpke package: Hybrid Public Key Encryption (RFC 9180) primitives and APIs.
"""

from .constants import AEADID, KDFID, KEMID
from .helpers import append_header, parse_header
from .primitives.aead import AEADBase
from .primitives.kdf import KDFBase
from .primitives.kem import DHKEM_P256, DHKEM_P384, DHKEM_P521, DHKEM_X448, DHKEM_X25519
from .setup import HPKESetup
from .single_shot import HPKESingleShot


class HPKE:
    """
    High-level HPKE interface exposing setup and single-shot helpers.
    """

    def __init__(self, kem_id: KEMID, kdf_id: KDFID, aead_id: AEADID):
        self.kem_id = kem_id
        self.kdf_id = kdf_id
        self.aead_id = aead_id
        self.kdf = self._create_kdf(kdf_id)
        self.kem = self._create_kem(kem_id)
        self.aead = self._create_aead(aead_id)
        self.setup = HPKESetup(self.kem, self.kdf, self.aead)
        self._single_shot = HPKESingleShot(self.setup)

    def _create_kdf(self, kdf_id: KDFID) -> KDFBase:
        return KDFBase(kdf_id)

    def _create_kem(self, kem_id: KEMID):
        if kem_id == KEMID.DHKEM_X25519_HKDF_SHA256:
            return DHKEM_X25519()
        if kem_id == KEMID.DHKEM_X448_HKDF_SHA512:
            return DHKEM_X448()
        if kem_id == KEMID.DHKEM_P256_HKDF_SHA256:
            return DHKEM_P256()
        if kem_id == KEMID.DHKEM_P384_HKDF_SHA384:
            return DHKEM_P384()
        if kem_id == KEMID.DHKEM_P521_HKDF_SHA512:
            return DHKEM_P521()
        raise ValueError(f"Unsupported KEM ID: {kem_id}")

    def _create_aead(self, aead_id: AEADID) -> AEADBase:
        return AEADBase(aead_id)

    # Single-shot convenience
    def seal_base(self, pkR, info: bytes, aad: bytes, pt: bytes):
        return self._single_shot.seal_base(pkR, info, aad, pt)

    def open_base(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes):
        return self._single_shot.open_base(enc, skR, info, aad, ct)

    def seal_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes):
        return self._single_shot.seal_psk(pkR, info, aad, pt, psk, psk_id)

    def open_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes):
        return self._single_shot.open_psk(enc, skR, info, aad, ct, psk, psk_id)

    def seal_auth(self, pkR, info: bytes, aad: bytes, pt: bytes, skS):
        return self._single_shot.seal_auth(pkR, info, aad, pt, skS)

    def open_auth(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, pkS):
        return self._single_shot.open_auth(enc, skR, info, aad, ct, pkS)

    def seal_auth_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes, skS):
        return self._single_shot.seal_auth_psk(pkR, info, aad, pt, psk, psk_id, skS)

    def open_auth_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes, pkS):
        return self._single_shot.open_auth_psk(enc, skR, info, aad, ct, psk, psk_id, pkS)


def create_hpke(
    kem_id: KEMID = KEMID.DHKEM_X25519_HKDF_SHA256,
    kdf_id: KDFID = KDFID.HKDF_SHA256,
    aead_id: AEADID = AEADID.AES_128_GCM,
) -> HPKE:
    return HPKE(kem_id, kdf_id, aead_id)

__all__ = [
    "KEMID",
    "KDFID",
    "AEADID",
    "HPKE",
    "create_hpke",
    "append_header",
    "parse_header",
]


