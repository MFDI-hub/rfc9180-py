from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from ..constants import AEAD_PARAMS, AEADID
from ..exceptions import MessageLimitReachedError, OpenError


class AEADBase:
    """
    Base class for AEAD wrappers.

    Provides authenticated encryption with associated data (AEAD) operations
    for HPKE. Supports AES-GCM and ChaCha20-Poly1305.

    Parameters
    ----------
    aead_id : AEADID
        AEAD algorithm identifier.

    Attributes
    ----------
    aead_id : AEADID
        AEAD algorithm identifier.
    Nk : int
        Key length in bytes.
    Nn : int
        Nonce length in bytes.
    Nt : int
        Tag length in bytes.
    cipher : callable or None
        Cipher factory function.
    max_seq : int
        Maximum sequence number before overflow.
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
        """
        Get cipher factory function for the AEAD algorithm.

        Returns
        -------
        callable or None
            Cipher factory function, or None for EXPORT_ONLY mode.

        Raises
        ------
        ValueError
            If AEAD ID is unsupported.
        """
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
        """
        Seal (encrypt and authenticate) a message.

        Parameters
        ----------
        key : bytes
            Encryption key (must be Nk bytes).
        nonce : bytes
            Nonce (must be Nn bytes).
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            Ciphertext (includes authentication tag).

        Raises
        ------
        ValueError
            If AEAD is EXPORT_ONLY, or if key/nonce lengths are invalid.
        MessageLimitReachedError
            If nonce reuse or limits exceeded.
        """
        if self.aead_id == AEADID.EXPORT_ONLY:
            raise ValueError("EXPORT_ONLY AEAD cannot seal messages")
        if len(key) != self.Nk:
            raise ValueError(f"Invalid key length: {len(key)}")
        if len(nonce) != self.Nn:
            raise ValueError(f"Invalid nonce length: {len(nonce)}")
        try:
            return self.cipher(key).encrypt(nonce, pt, aad)  # type: ignore[no-any-return]
        except Exception as e:
            # Commonly thrown when nonce reuse or limits exceeded
            raise MessageLimitReachedError(f"Seal failed: {e}") from e

    def open(self, key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
        """
        Open (decrypt and verify) a message.

        Parameters
        ----------
        key : bytes
            Encryption key (must be Nk bytes).
        nonce : bytes
            Nonce (must be Nn bytes).
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt (includes authentication tag).

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        ValueError
            If AEAD is EXPORT_ONLY, or if key/nonce lengths are invalid.
        OpenError
            If decryption or authentication fails.
        """
        if self.aead_id == AEADID.EXPORT_ONLY:
            raise ValueError("EXPORT_ONLY AEAD cannot open messages")
        if len(key) != self.Nk:
            raise ValueError(f"Invalid key length: {len(key)}")
        if len(nonce) != self.Nn:
            raise ValueError(f"Invalid nonce length: {len(nonce)}")
        try:
            return self.cipher(key).decrypt(nonce, ct, aad)  # type: ignore[no-any-return]
        except Exception as e:
            raise OpenError(f"Decryption failed: {e}") from e


