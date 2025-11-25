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

    This class provides a convenient interface for Hybrid Public Key Encryption
    (HPKE) operations as specified in RFC 9180. It supports all HPKE modes:
    Base, PSK, Auth, and AuthPSK.

    Parameters
    ----------
    kem_id : KEMID
        The Key Encapsulation Mechanism identifier.
    kdf_id : KDFID
        The Key Derivation Function identifier.
    aead_id : AEADID
        The Authenticated Encryption with Associated Data identifier.

    Attributes
    ----------
    kem_id : KEMID
        The Key Encapsulation Mechanism identifier.
    kdf_id : KDFID
        The Key Derivation Function identifier.
    aead_id : AEADID
        The Authenticated Encryption with Associated Data identifier.
    kem : KEMBase
        The KEM instance for key encapsulation/decapsulation.
    kdf : KDFBase
        The KDF instance for key derivation.
    aead : AEADBase
        The AEAD instance for encryption/decryption.
    setup : HPKESetup
        The HPKE setup instance for context creation.

    Raises
    ------
    ValueError
        If the KEM ID is unsupported.
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
        """
        Create a KDF instance for the given KDF ID.

        Parameters
        ----------
        kdf_id : KDFID
            The KDF identifier.

        Returns
        -------
        KDFBase
            A KDFBase instance.
        """
        return KDFBase(kdf_id)

    def _create_kem(self, kem_id: KEMID):
        """
        Create a KEM instance for the given KEM ID.

        Parameters
        ----------
        kem_id : KEMID
            The KEM identifier.

        Returns
        -------
        KEMBase
            A KEMBase instance (DHKEM_X25519, DHKEM_X448, DHKEM_P256, etc.).

        Raises
        ------
        ValueError
            If the KEM ID is unsupported.
        """
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
        """
        Create an AEAD instance for the given AEAD ID.

        Parameters
        ----------
        aead_id : AEADID
            The AEAD identifier.

        Returns
        -------
        AEADBase
            An AEADBase instance.
        """
        return AEADBase(aead_id)

    def _deserialize_public_key(self, pk):
        """
        Deserialize public key from bytes if needed.

        Parameters
        ----------
        pk : bytes or Key Object
            Public key as bytes or Key Object.

        Returns
        -------
        Key Object
            Public key as Key Object.
        """
        if isinstance(pk, bytes):
            return self.kem.deserialize_public_key(pk)
        return pk

    def _deserialize_private_key(self, sk):
        """
        Deserialize private key from bytes if needed.

        Parameters
        ----------
        sk : bytes or Key Object
            Private key as bytes or Key Object.

        Returns
        -------
        Key Object
            Private key as Key Object.
        """
        if isinstance(sk, bytes):
            return self.kem.deserialize_private_key(sk)
        return sk

    # Key generation methods
    def generate_key_pair(self):
        """
        Generate a new key pair for the configured KEM.

        Returns
        -------
        tuple
            Tuple of (private_key, public_key) as Key Objects from the
            cryptography library.
        """
        return self.kem.generate_key_pair()

    def derive_key_pair(self, seed: bytes):
        """
        Derive a key pair from a seed using the configured KEM.

        Parameters
        ----------
        seed : bytes
            Input key material (IKM) for key derivation.

        Returns
        -------
        tuple
            Tuple of (private_key, public_key) as Key Objects from the
            cryptography library.

        Raises
        ------
        ValueError
            If seed is too short for the KEM requirements.
        """
        return self.kem.derive_key_pair(seed)

    def serialize_public_key(self, pk) -> bytes:
        """
        Serialize a public key to bytes.

        Parameters
        ----------
        pk : bytes or Key Object
            Public key (Key Object or bytes).

        Returns
        -------
        bytes
            Serialized public key as bytes.
        """
        if isinstance(pk, bytes):
            return pk
        return self.kem.serialize_public_key(pk)

    def serialize_private_key(self, sk) -> bytes:
        """
        Serialize a private key to bytes.

        Parameters
        ----------
        sk : bytes or Key Object
            Private key (Key Object or bytes).

        Returns
        -------
        bytes
            Serialized private key as bytes.
        """
        if isinstance(sk, bytes):
            return sk
        return self.kem.serialize_private_key(sk)

    # Single-shot convenience
    def seal_base(self, pkR, info: bytes, aad: bytes, pt: bytes):
        """
        Seal (encrypt) a message using Base mode.

        Parameters
        ----------
        pkR : bytes or Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, ciphertext).
        """
        pkR = self._deserialize_public_key(pkR)
        return self._single_shot.seal_base(pkR, info, aad, pt)

    def open_base(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes):
        """
        Open (decrypt) a message using Base mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : bytes or Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        OpenError
            If decryption fails.
        """
        skR = self._deserialize_private_key(skR)
        return self._single_shot.open_base(enc, skR, info, aad, ct)

    def seal_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes):
        """
        Seal (encrypt) a message using PSK mode.

        Parameters
        ----------
        pkR : bytes or Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, ciphertext).

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        pkR = self._deserialize_public_key(pkR)
        return self._single_shot.seal_psk(pkR, info, aad, pt, psk, psk_id)

    def open_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes):
        """
        Open (decrypt) a message using PSK mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : bytes or Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        OpenError
            If decryption fails.
        """
        skR = self._deserialize_private_key(skR)
        return self._single_shot.open_psk(enc, skR, info, aad, ct, psk, psk_id)

    def seal_auth(self, pkR, info: bytes, aad: bytes, pt: bytes, skS):
        """
        Seal (encrypt) a message using Auth mode.

        Parameters
        ----------
        pkR : bytes or Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.
        skS : bytes or Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, ciphertext).
        """
        pkR = self._deserialize_public_key(pkR)
        skS = self._deserialize_private_key(skS)
        return self._single_shot.seal_auth(pkR, info, aad, pt, skS)

    def open_auth(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, pkS):
        """
        Open (decrypt) a message using Auth mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : bytes or Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt.
        pkS : bytes or Key Object
            Sender's public key.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        OpenError
            If decryption fails.
        """
        skR = self._deserialize_private_key(skR)
        pkS = self._deserialize_public_key(pkS)
        return self._single_shot.open_auth(enc, skR, info, aad, ct, pkS)

    def seal_auth_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes, skS):
        """
        Seal (encrypt) a message using AuthPSK mode.

        Parameters
        ----------
        pkR : bytes or Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.
        skS : bytes or Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, ciphertext).

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        pkR = self._deserialize_public_key(pkR)
        skS = self._deserialize_private_key(skS)
        return self._single_shot.seal_auth_psk(pkR, info, aad, pt, psk, psk_id, skS)

    def open_auth_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes, pkS):
        """
        Open (decrypt) a message using AuthPSK mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : bytes or Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.
        pkS : bytes or Key Object
            Sender's public key.

        Returns
        -------
        bytes
            Decrypted plaintext.

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        OpenError
            If decryption fails.
        """
        skR = self._deserialize_private_key(skR)
        pkS = self._deserialize_public_key(pkS)
        return self._single_shot.open_auth_psk(enc, skR, info, aad, ct, psk, psk_id, pkS)


def create_hpke(
    kem_id: KEMID = KEMID.DHKEM_X25519_HKDF_SHA256,
    kdf_id: KDFID = KDFID.HKDF_SHA256,
    aead_id: AEADID = AEADID.AES_128_GCM,
) -> HPKE:
    """
    Create an HPKE instance with default or specified algorithms.

    Parameters
    ----------
    kem_id : KEMID, optional
        Key Encapsulation Mechanism identifier. Defaults to
        DHKEM_X25519_HKDF_SHA256.
    kdf_id : KDFID, optional
        Key Derivation Function identifier. Defaults to HKDF_SHA256.
    aead_id : AEADID, optional
        Authenticated Encryption with Associated Data identifier.
        Defaults to AES_128_GCM.

    Returns
    -------
    HPKE
        An HPKE instance configured with the specified algorithms.

    Raises
    ------
    ValueError
        If the KEM ID is unsupported.
    """
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


