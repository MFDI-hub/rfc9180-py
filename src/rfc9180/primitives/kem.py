from abc import ABC, abstractmethod
from typing import cast
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519

from ..constants import KDFID, KEM_PARAMS, KEMID
from ..exceptions import (
    DecapError,
    DeriveKeyPairError,
    DeserializeError,
    EncapError,
    ValidationError,
)
from ..utils import I2OSP, OS2IP, concat
from .kdf import KDFBase


class KEMBase(ABC):
    """
    Base class for DHKEM implementations.

    Provides Diffie-Hellman-based Key Encapsulation Mechanism operations
    as specified in RFC 9180 §7.1.

    Parameters
    ----------
    kem_id : KEMID
        KEM algorithm identifier.

    Attributes
    ----------
    kem_id : KEMID
        KEM algorithm identifier.
    kdf : KDFBase
        Internal KDF instance for the KEM.
    Nsecret : int
        Shared secret length in bytes.
    Nenc : int
        Encapsulated key length in bytes.
    Npk : int
        Public key length in bytes.
    Nsk : int
        Private key length in bytes.
    Ndh : int
        DH shared secret length in bytes.
    suite_id : bytes
        KEM suite identifier.
    """

    def __init__(self, kem_id: KEMID):
        self.kem_id = kem_id
        self.kdf = self._create_internal_kdf(kem_id)
        params = KEM_PARAMS[kem_id]
        self.Nsecret = params['Nsecret']
        self.Nenc = params['Nenc']
        self.Npk = params['Npk']
        self.Nsk = params['Nsk']
        self.Ndh = params['Ndh']
        # KEM suite id (RFC 9180 §4.1)
        self.suite_id = concat(b"KEM", I2OSP(kem_id, 2))

    def _create_internal_kdf(self, kem_id: KEMID) -> KDFBase:
        """
        Create internal KDF instance for the KEM.

        Parameters
        ----------
        kem_id : KEMID
            KEM algorithm identifier.

        Returns
        -------
        KDFBase
            KDF instance.

        Raises
        ------
        ValueError
            If KEM ID is unknown.
        """
        mapping = {
            KEMID.DHKEM_P256_HKDF_SHA256: KDFID.HKDF_SHA256,
            KEMID.DHKEM_P384_HKDF_SHA384: KDFID.HKDF_SHA384,
            KEMID.DHKEM_P521_HKDF_SHA512: KDFID.HKDF_SHA512,
            KEMID.DHKEM_X25519_HKDF_SHA256: KDFID.HKDF_SHA256,
            KEMID.DHKEM_X448_HKDF_SHA512: KDFID.HKDF_SHA512,
        }
        if kem_id not in mapping:
            raise ValueError(f"Unknown KEM ID: {kem_id}")
        return KDFBase(mapping[kem_id])

    @abstractmethod
    def generate_key_pair(self):
        """
        Generate a new key pair.

        Returns
        -------
        tuple
            Tuple of (private_key, public_key) as Key Objects.
        """
        pass

    @abstractmethod
    def derive_key_pair(self, ikm: bytes):
        """
        Derive a key pair from input key material.

        Parameters
        ----------
        ikm : bytes
            Input key material.

        Returns
        -------
        tuple
            Tuple of (private_key, public_key) as Key Objects.

        Raises
        ------
        ValueError
            If IKM is too short.
        DeriveKeyPairError
            If derivation fails (e.g., rejection sampling exceeded).
        """
        pass

    @abstractmethod
    def serialize_public_key(self, pk) -> bytes:
        """
        Serialize a public key to bytes.

        Parameters
        ----------
        pk : Key Object
            Public key.

        Returns
        -------
        bytes
            Serialized public key.
        """
        pass

    @abstractmethod
    def deserialize_public_key(self, pkm: bytes):
        """
        Deserialize a public key from bytes.

        Parameters
        ----------
        pkm : bytes
            Serialized public key.

        Returns
        -------
        Key Object
            Public key.

        Raises
        ------
        DeserializeError
            If deserialization fails.
        """
        pass

    @abstractmethod
    def serialize_private_key(self, sk) -> bytes:
        """
        Serialize a private key to bytes.

        Parameters
        ----------
        sk : Key Object
            Private key.

        Returns
        -------
        bytes
            Serialized private key.
        """
        pass

    @abstractmethod
    def deserialize_private_key(self, skm: bytes):
        """
        Deserialize a private key from bytes.

        Parameters
        ----------
        skm : bytes
            Serialized private key.

        Returns
        -------
        Key Object
            Private key.

        Raises
        ------
        DeserializeError
            If deserialization fails.
        """
        pass

    @abstractmethod
    def dh(self, sk, pk) -> bytes:
        """
        Perform Diffie-Hellman key exchange.

        Parameters
        ----------
        sk : Key Object
            Private key.
        pk : Key Object
            Public key.

        Returns
        -------
        bytes
            Shared secret.

        Raises
        ------
        ValidationError
            If DH operation fails or output is invalid.
        """
        pass

    @abstractmethod
    def _get_public_key(self, sk):
        """
        Get public key from private key.

        Parameters
        ----------
        sk : Key Object
            Private key.

        Returns
        -------
        Key Object
            Public key.
        """
        pass

    def extract_and_expand(self, dh_value: bytes, kem_context: bytes) -> bytes:
        """
        RFC 9180 §4.1 - ExtractAndExpand.

        Parameters
        ----------
        dh_value : bytes
            Diffie-Hellman shared secret.
        kem_context : bytes
            KEM context.

        Returns
        -------
        bytes
            Shared secret (Nsecret bytes).
        """
        eae_prk = self.kdf.labeled_extract(
            salt=b"",
            label="eae_prk",
            ikm=dh_value,
            suite_id=self.suite_id,
        )
        shared_secret = self.kdf.labeled_expand(
            prk=eae_prk,
            label="shared_secret",
            info=kem_context,
            L=self.Nsecret,
            suite_id=self.suite_id,
        )
        return shared_secret

    def encap(self, pkR):
        """
        Base/PSK encapsulation.

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.

        Returns
        -------
        tuple
            Tuple of (shared_secret, encapsulated_key).

        Raises
        ------
        EncapError
            If encapsulation fails.
        """
        try:
            skE, pkE = self.generate_key_pair()
            dh_value = self.dh(skE, pkR)
            enc = self.serialize_public_key(pkE)
            pkRm = self.serialize_public_key(pkR)
            kem_context = concat(enc, pkRm)
            return self.extract_and_expand(dh_value, kem_context), enc
        except Exception as e:
            raise EncapError(f"Encapsulation failed: {e}") from e

    def decap(self, enc: bytes, skR):
        """
        Base/PSK decapsulation.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.

        Returns
        -------
        bytes
            Shared secret.

        Raises
        ------
        DecapError
            If decapsulation fails.
        """
        try:
            pkE = self.deserialize_public_key(enc)
            dh_value = self.dh(skR, pkE)
            pkR = self._get_public_key(skR)
            pkRm = self.serialize_public_key(pkR)
            kem_context = concat(enc, pkRm)
            return self.extract_and_expand(dh_value, kem_context)
        except Exception as e:
            raise DecapError(f"Decapsulation failed: {e}") from e

    def auth_encap(self, pkR, skS):
        """
        Authenticated encapsulation (Auth/AuthPSK).

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        skS : Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (shared_secret, encapsulated_key).

        Raises
        ------
        EncapError
            If encapsulation fails.
        """
        try:
            skE, pkE = self.generate_key_pair()
            dh_value = concat(self.dh(skE, pkR), self.dh(skS, pkR))
            enc = self.serialize_public_key(pkE)
            pkRm = self.serialize_public_key(pkR)
            pkS_pub = self._get_public_key(skS)
            pkSm = self.serialize_public_key(pkS_pub)
            kem_context = concat(enc, pkRm, pkSm)
            return self.extract_and_expand(dh_value, kem_context), enc
        except Exception as e:
            raise EncapError(f"Authenticated encapsulation failed: {e}") from e

    def auth_decap(self, enc: bytes, skR, pkS):
        """
        Authenticated decapsulation (Auth/AuthPSK).

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        pkS : Key Object
            Sender's public key.

        Returns
        -------
        bytes
            Shared secret.

        Raises
        ------
        DecapError
            If decapsulation fails.
        """
        try:
            pkE = self.deserialize_public_key(enc)
            dh_value = concat(self.dh(skR, pkE), self.dh(skR, pkS))
            pkR = self._get_public_key(skR)
            pkRm = self.serialize_public_key(pkR)
            pkSm = self.serialize_public_key(pkS)
            kem_context = concat(enc, pkRm, pkSm)
            return self.extract_and_expand(dh_value, kem_context)
        except Exception as e:
            raise DecapError(f"Authenticated decapsulation failed: {e}") from e


class DHKEM_X25519(KEMBase):
    """
    DHKEM with X25519 and HKDF-SHA256.

    Implements DHKEM using the X25519 elliptic curve Diffie-Hellman
    function and HKDF-SHA256 for key derivation.
    """

    def __init__(self):
        super().__init__(KEMID.DHKEM_X25519_HKDF_SHA256)
        # Keep track of raw (unclamped) private bytes for derived keys so that
        # SerializePrivateKey matches RFC vectors.
        self._raw_private_bytes = {}

    def generate_key_pair(self):
        """
        Generate a new X25519 key pair.

        Returns
        -------
        tuple
            Tuple of (X25519PrivateKey, X25519PublicKey).
        """
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return sk, pk

    def derive_key_pair(self, ikm: bytes):
        """
        RFC 9180 §7.1.3 - DeriveKeyPair for X25519.

        Parameters
        ----------
        ikm : bytes
            Input key material (must be at least Nsk bytes).

        Returns
        -------
        tuple
            Tuple of (X25519PrivateKey, X25519PublicKey).

        Raises
        ------
        ValueError
            If IKM is too short.
        """
        if len(ikm) < self.Nsk:
            raise ValueError(f"IKM must be at least {self.Nsk} bytes")

        dkp_prk = self.kdf.labeled_extract(
            salt=b"",
            label="dkp_prk",
            ikm=ikm,
            suite_id=self.suite_id,
        )
        sk_bytes = self.kdf.labeled_expand(
            prk=dkp_prk,
            label="sk",
            info=b"",
            L=self.Nsk,
            suite_id=self.suite_id,
        )
        # Do not pre-clamp; underlying X25519 operations apply clamping
        # as required during scalar multiplication. Returning the raw
        # derived secret preserves vector parity for SerializePrivateKey.
        sk = x25519.X25519PrivateKey.from_private_bytes(sk_bytes)
        # Stash raw bytes for later serialization to match vectors
        self._raw_private_bytes[id(sk)] = sk_bytes
        pk = sk.public_key()
        return sk, pk

    def serialize_public_key(self, pk) -> bytes:
        return cast(bytes, pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ))

    def deserialize_public_key(self, pkm: bytes):
        if len(pkm) != self.Npk:
            raise DeserializeError(f"Invalid public key length: {len(pkm)}")
        try:
            return x25519.X25519PublicKey.from_public_bytes(pkm)
        except Exception as e:
            raise DeserializeError(f"Public key deserialization failed: {e}") from e

    def serialize_private_key(self, sk) -> bytes:
        # Prefer raw derived bytes when available to match RFC vectors
        raw = self._raw_private_bytes.get(id(sk))
        if raw is not None:
            return raw
        return sk.private_bytes(  # type: ignore[no-any-return]
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def deserialize_private_key(self, skm: bytes):
        if len(skm) != self.Nsk:
            raise DeserializeError(f"Invalid private key length: {len(skm)}")
        try:
            return x25519.X25519PrivateKey.from_private_bytes(skm)
        except Exception as e:
            raise DeserializeError(f"Private key deserialization failed: {e}") from e

    def dh(self, sk, pk) -> bytes:
        try:
            shared = sk.exchange(pk)
            if shared == b"\x00" * 32:
                raise ValidationError("DH output is all-zero")
            return shared  # type: ignore[no-any-return]
        except Exception as e:
            raise ValidationError(f"DH operation failed: {e}") from e

    def _get_public_key(self, sk):
        return sk.public_key()


class DHKEM_X448(KEMBase):
    """
    DHKEM with X448 and HKDF-SHA512.

    Implements DHKEM using the X448 elliptic curve Diffie-Hellman
    function and HKDF-SHA512 for key derivation.
    """

    def __init__(self):
        super().__init__(KEMID.DHKEM_X448_HKDF_SHA512)
        self._raw_private_bytes = {}

    def generate_key_pair(self):
        sk = x448.X448PrivateKey.generate()
        pk = sk.public_key()
        return sk, pk

    def derive_key_pair(self, ikm: bytes):
        if len(ikm) < self.Nsk:
            raise ValueError(f"IKM must be at least {self.Nsk} bytes")

        dkp_prk = self.kdf.labeled_extract(
            salt=b"",
            label="dkp_prk",
            ikm=ikm,
            suite_id=self.suite_id,
        )
        sk_bytes = self.kdf.labeled_expand(
            prk=dkp_prk,
            label="sk",
            info=b"",
            L=self.Nsk,
            suite_id=self.suite_id,
        )
        # Do not pre-clamp for X448 either; rely on implementation to
        # enforce clamping during multiplication so that serialized
        # secret matches vectors.
        sk = x448.X448PrivateKey.from_private_bytes(sk_bytes)
        self._raw_private_bytes[id(sk)] = sk_bytes
        pk = sk.public_key()
        return sk, pk

    def serialize_public_key(self, pk) -> bytes:
        return cast(bytes, pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ))

    def deserialize_public_key(self, pkm: bytes):
        if len(pkm) != self.Npk:
            raise DeserializeError(f"Invalid public key length: {len(pkm)}")
        try:
            return x448.X448PublicKey.from_public_bytes(pkm)
        except Exception as e:
            raise DeserializeError(f"Public key deserialization failed: {e}") from e

    def serialize_private_key(self, sk) -> bytes:
        raw = self._raw_private_bytes.get(id(sk))
        if raw is not None:
            return raw
        return sk.private_bytes(  # type: ignore[no-any-return]
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def deserialize_private_key(self, skm: bytes):
        if len(skm) != self.Nsk:
            raise DeserializeError(f"Invalid private key length: {len(skm)}")
        try:
            return x448.X448PrivateKey.from_private_bytes(skm)
        except Exception as e:
            raise DeserializeError(f"Private key deserialization failed: {e}") from e

    def dh(self, sk, pk) -> bytes:
        try:
            shared = sk.exchange(pk)
            if shared == b"\x00" * 56:
                raise ValidationError("DH output is all-zero")
            return shared  # type: ignore[no-any-return]
        except Exception as e:
            raise ValidationError(f"DH operation failed: {e}") from e

    def _get_public_key(self, sk):
        return sk.public_key()


class DHKEM_NIST(KEMBase):
    """
    Base for NIST P-curves (P-256, P-384, P-521).

    Implements DHKEM using NIST elliptic curves with ECDH and
    rejection sampling for key derivation.

    Parameters
    ----------
    kem_id : KEMID
        KEM algorithm identifier.
    curve
        Elliptic curve instance.
    order : int
        Curve order for rejection sampling.
    """

    def __init__(self, kem_id: KEMID, curve, order: int, mask: int = 0xFF):
        super().__init__(kem_id)
        self.curve = curve
        self.order = order
        self.mask = mask

    def generate_key_pair(self):
        sk = ec.generate_private_key(self.curve)
        pk = sk.public_key()
        return sk, pk

    def derive_key_pair(self, ikm: bytes):
        if len(ikm) < self.Nsk:
            raise ValueError(f"IKM must be at least {self.Nsk} bytes")

        dkp_prk = self.kdf.labeled_extract(
            salt=b"",
            label="dkp_prk",
            ikm=ikm,
            suite_id=self.suite_id,
        )
        counter = 0
        while True:
            if counter > 255:
                raise DeriveKeyPairError("Rejection sampling exceeded 255 iterations")
            candidate = self.kdf.labeled_expand(
                prk=dkp_prk,
                label="candidate",
                info=I2OSP(counter, 1),
                L=self.Nsk,
                suite_id=self.suite_id,
            )
            if self.mask != 0xFF:
                # Convert to bytearray to modify, then back to bytes
                b = bytearray(candidate)
                b[0] &= self.mask
                candidate = bytes(b)
            scalar = OS2IP(candidate)
            if 1 <= scalar < self.order:
                break
            counter += 1
        sk = ec.derive_private_key(scalar, self.curve)
        pk = sk.public_key()
        return sk, pk

    def serialize_public_key(self, pk) -> bytes:
        return pk.public_bytes(  # type: ignore[no-any-return]
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def deserialize_public_key(self, pkm: bytes):
        if len(pkm) != self.Npk:
            raise DeserializeError(f"Invalid public key length: {len(pkm)}")
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(self.curve, pkm)
        except Exception as e:
            raise DeserializeError(f"Public key deserialization failed: {e}") from e

    def serialize_private_key(self, sk) -> bytes:
        priv = sk.private_numbers().private_value
        return I2OSP(priv, self.Nsk)

    def deserialize_private_key(self, skm: bytes):
        if len(skm) != self.Nsk:
            raise DeserializeError(f"Invalid private key length: {len(skm)}")
        scalar = OS2IP(skm)
        if not (1 <= scalar < self.order):
            raise DeserializeError("Private key scalar out of range")
        try:
            return ec.derive_private_key(scalar, self.curve)
        except Exception as e:
            raise DeserializeError(f"Private key deserialization failed: {e}") from e

    def dh(self, sk, pk) -> bytes:
        try:
            return sk.exchange(ec.ECDH(), pk)  # type: ignore[no-any-return]
        except Exception as e:
            raise ValidationError(f"DH operation failed: {e}") from e

    def _get_public_key(self, sk):
        return sk.public_key()


class DHKEM_P256(DHKEM_NIST):
    """
    DHKEM with P-256 and HKDF-SHA256.

    Implements DHKEM using the NIST P-256 curve (secp256r1) and
    HKDF-SHA256 for key derivation.
    """
    def __init__(self):
        super().__init__(
            KEMID.DHKEM_P256_HKDF_SHA256,
            ec.SECP256R1(),
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        )


class DHKEM_P384(DHKEM_NIST):
    """
    DHKEM with P-384 and HKDF-SHA384.

    Implements DHKEM using the NIST P-384 curve (secp384r1) and
    HKDF-SHA384 for key derivation.
    """
    def __init__(self):
        super().__init__(
            KEMID.DHKEM_P384_HKDF_SHA384,
            ec.SECP384R1(),
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        )


class DHKEM_P521(DHKEM_NIST):
    """
    DHKEM with P-521 and HKDF-SHA512.

    Implements DHKEM using the NIST P-521 curve (secp521r1) and
    HKDF-SHA512 for key derivation.
    """
    def __init__(self):
        super().__init__(
            KEMID.DHKEM_P521_HKDF_SHA512,
            ec.SECP521R1(),
            0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
            0x01, # mask
        )
