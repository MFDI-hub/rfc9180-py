from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..constants import AEADID, AEAD_PARAMS
from ..exceptions import OpenError, MessageLimitReachedError


class AEADBase:
    """
    Base class for AEAD wrappers.
    """

    def __init__(self, aead_id: AEADID):
        self.aead_id = aead_id
        params = AEAD_PARAMS[aead_id]
        self.Nk = params['Nk']
        self.Nn = params['Nn']
        self.Nt = params['Nt']
        self.cipher = self._get_cipher()
        self.max_seq = (1 << (8 * self.Nn)) - 1 if self.Nn > 0 else 0

    def _get_cipher(self):
        if self.aead_id == AEADID.AES_128_GCM:
            return lambda key: AESGCM(key)
        if self.aead_id == AEADID.AES_256_GCM:
            return lambda key: AESGCM(key)
        if self.aead_id == AEADID.CHACHA20_POLY1305:
            return lambda key: ChaCha20Poly1305(key)
        if self.aead_id == AEADID.EXPORT_ONLY:
            return None
        raise ValueError(f"Unsupported AEAD ID: {self.aead_id}")

    def seal(self, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
        if self.aead_id == AEADID.EXPORT_ONLY:
            raise ValueError("EXPORT_ONLY AEAD cannot seal messages")
        if len(key) != self.Nk:
            raise ValueError(f"Invalid key length: {len(key)}")
        if len(nonce) != self.Nn:
            raise ValueError(f"Invalid nonce length: {len(nonce)}")
        try:
            return self.cipher(key).encrypt(nonce, pt, aad)
        except Exception as e:
            # Commonly thrown when nonce reuse or limits exceeded
            raise MessageLimitReachedError(f"Seal failed: {e}")

    def open(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
        if self.aead_id == AEADID.EXPORT_ONLY:
            raise ValueError("EXPORT_ONLY AEAD cannot open messages")
        if len(key) != self.Nk:
            raise ValueError(f"Invalid key length: {len(key)}")
        if len(nonce) != self.Nn:
            raise ValueError(f"Invalid nonce length: {len(nonce)}")
        try:
            return self.cipher(key).decrypt(nonce, ct, aad)
        except Exception as e:
            raise OpenError(f"Decryption failed: {e}")


