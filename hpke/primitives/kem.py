from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ec

from ..constants import KEMID, KEM_PARAMS
from ..exceptions import EncapError, DecapError, ValidationError, DeserializeError, DeriveKeyPairError
from ..utils import I2OSP, concat, OS2IP


class KEMBase(ABC):
    """
    Base class for DHKEM implementations.
    """

    def __init__(self, kem_id: KEMID, kdf: 'KDFBase'):
        self.kem_id = kem_id
        self.kdf = kdf
        params = KEM_PARAMS[kem_id]
        self.Nsecret = params['Nsecret']
        self.Nenc = params['Nenc']
        self.Npk = params['Npk']
        self.Nsk = params['Nsk']
        self.Ndh = params['Ndh']
        # KEM suite id
        self.suite_id = concat(b"KEM", I2OSP(kem_id, 2))

    @abstractmethod
    def generate_key_pair(self):
        pass

    @abstractmethod
    def derive_key_pair(self, ikm: bytes):
        pass

    @abstractmethod
    def serialize_public_key(self, pk) -> bytes:
        pass

    @abstractmethod
    def deserialize_public_key(self, pkm: bytes):
        pass

    @abstractmethod
    def serialize_private_key(self, sk) -> bytes:
        pass

    @abstractmethod
    def deserialize_private_key(self, skm: bytes):
        pass

    @abstractmethod
    def dh(self, sk, pk) -> bytes:
        pass

    @abstractmethod
    def _get_public_key(self, sk):
        pass

    def extract_and_expand(self, dh_value: bytes, kem_context: bytes) -> bytes:
        """
        RFC 9180 §4.1 - ExtractAndExpand
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
        """
        try:
            skE, pkE = self.generate_key_pair()
            dh_value = self.dh(skE, pkR)
            enc = self.serialize_public_key(pkE)
            pkRm = self.serialize_public_key(pkR)
            kem_context = concat(enc, pkRm)
            return self.extract_and_expand(dh_value, kem_context), enc
        except Exception as e:
            raise EncapError(f"Encapsulation failed: {e}")

    def decap(self, enc: bytes, skR):
        """
        Base/PSK decapsulation.
        """
        try:
            pkE = self.deserialize_public_key(enc)
            dh_value = self.dh(skR, pkE)
            pkR = self._get_public_key(skR)
            pkRm = self.serialize_public_key(pkR)
            kem_context = concat(enc, pkRm)
            return self.extract_and_expand(dh_value, kem_context)
        except Exception as e:
            raise DecapError(f"Decapsulation failed: {e}")

    def auth_encap(self, pkR, skS):
        """
        Authenticated encapsulation (Auth/AuthPSK).
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
            raise EncapError(f"Authenticated encapsulation failed: {e}")

    def auth_decap(self, enc: bytes, skR, pkS):
        """
        Authenticated decapsulation (Auth/AuthPSK).
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
            raise DecapError(f"Authenticated decapsulation failed: {e}")


class DHKEM_X25519(KEMBase):
    """
    DHKEM with X25519 and HKDF-SHA256.
    """

    def __init__(self, kdf: 'KDFBase'):
        super().__init__(KEMID.DHKEM_X25519_HKDF_SHA256, kdf)

    def generate_key_pair(self):
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return sk, pk

    def derive_key_pair(self, ikm: bytes):
        """
        RFC 9180 §7.1.3 - DeriveKeyPair for X25519
        """
        if len(ikm) < self.Nsk:
            raise ValueError(f"IKM must be at least {self.Nsk} bytes")

        dkp_prk = self.kdf.labeled_extract(
            salt=b"",
            label="dkp_prk",
            ikm=ikm,
            suite_id=self.suite_id,
        )
        sk_bytes = bytearray(
            self.kdf.labeled_expand(
                prk=dkp_prk,
                label="sk",
                info=b"",
                L=self.Nsk,
                suite_id=self.suite_id,
            )
        )
        # Clamp per RFC 7748
        sk_bytes[0] &= 248
        sk_bytes[31] &= 127
        sk_bytes[31] |= 64
        sk = x25519.X25519PrivateKey.from_private_bytes(bytes(sk_bytes))
        pk = sk.public_key()
        return sk, pk

    def serialize_public_key(self, pk) -> bytes:
        return pk.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def deserialize_public_key(self, pkm: bytes):
        if len(pkm) != self.Npk:
            raise DeserializeError(f"Invalid public key length: {len(pkm)}")
        try:
            return x25519.X25519PublicKey.from_public_bytes(pkm)
        except Exception as e:
            raise DeserializeError(f"Public key deserialization failed: {e}")

    def serialize_private_key(self, sk) -> bytes:
        return sk.private_bytes(
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
            raise DeserializeError(f"Private key deserialization failed: {e}")

    def dh(self, sk, pk) -> bytes:
        try:
            shared = sk.exchange(pk)
            if shared == b"\x00" * 32:
                raise ValidationError("DH output is all-zero")
            return shared
        except Exception as e:
            raise ValidationError(f"DH operation failed: {e}")

    def _get_public_key(self, sk):
        return sk.public_key()


class DHKEM_P256(KEMBase):
    """
    DHKEM with P-256 and HKDF-SHA256.
    """

    def __init__(self, kdf: 'KDFBase'):
        super().__init__(KEMID.DHKEM_P256_HKDF_SHA256, kdf)
        self.curve = ec.SECP256R1()
        # Order of the P-256 curve
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    def generate_key_pair(self):
        sk = ec.generate_private_key(self.curve)
        pk = sk.public_key()
        return sk, pk

    def derive_key_pair(self, ikm: bytes):
        """
        RFC 9180 §7.1.3 - NIST curve key derivation with rejection sampling.
        """
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
            scalar = OS2IP(candidate)
            if 1 <= scalar < self.order:
                break
            counter += 1
        sk = ec.derive_private_key(scalar, self.curve)
        pk = sk.public_key()
        return sk, pk

    def serialize_public_key(self, pk) -> bytes:
        return pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def deserialize_public_key(self, pkm: bytes):
        if len(pkm) != self.Npk:
            raise DeserializeError(f"Invalid public key length: {len(pkm)}")
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(self.curve, pkm)
        except Exception as e:
            raise DeserializeError(f"Public key deserialization failed: {e}")

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
            raise DeserializeError(f"Private key deserialization failed: {e}")

    def dh(self, sk, pk) -> bytes:
        try:
            shared = sk.exchange(ec.ECDH(), pk)
            return shared
        except Exception as e:
            raise ValidationError(f"DH operation failed: {e}")

    def _get_public_key(self, sk):
        return sk.public_key()
