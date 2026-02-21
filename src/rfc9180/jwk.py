import json
from abc import ABC, abstractmethod
from typing import Any, Union, cast

from cryptography.hazmat.primitives.asymmetric import ec, x448, x25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from .types import KEMKey as RawKEMKey
from .utils import base64url_decode

_SUPPORTED_JWK_KTYS = {"EC", "OKP"}
_SUPPORTED_EC_CRVS = {"P-256", "P-384", "P-521"}


class KEMKeyInterface(ABC):
    def __init__(self, key: RawKEMKey) -> None:
        self._key = key

    @property
    def raw(self) -> RawKEMKey:
        return self._key

    @abstractmethod
    def to_private_bytes(self) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def to_public_bytes(self) -> bytes:
        raise NotImplementedError()


class ECKey(KEMKeyInterface):
    def __init__(self, key: Union[EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> None:
        super().__init__(key)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> "ECKey":
        if jwk.get("kty") != "EC":
            raise ValueError(f"kty is not EC: {jwk.get('kty')}.")
        if "x" not in jwk or "y" not in jwk:
            raise ValueError("x and y are required for EC JWK")
        crv_name = jwk.get("crv")
        if crv_name not in _SUPPORTED_EC_CRVS:
            raise ValueError(f"Unknown crv: {crv_name}.")

        x = base64url_decode(jwk["x"])
        y = base64url_decode(jwk["y"])

        if crv_name == "P-256":
            expected_len = 32
            crv: ec.EllipticCurve = ec.SECP256R1()
        elif crv_name == "P-384":
            expected_len = 48
            crv = ec.SECP384R1()
        else:
            expected_len = 66
            crv = ec.SECP521R1()

        if len(x) != expected_len or len(y) != expected_len:
            raise ValueError(f"Coordinates must be {expected_len} bytes for curve {crv_name}")

        public_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=crv,
        )
        if "d" not in jwk:
            return cls(public_numbers.public_key())

        d = base64url_decode(jwk["d"])
        if len(d) != expected_len:
            raise ValueError(f"d must be {expected_len} bytes for curve {crv_name}")
        private_numbers = ec.EllipticCurvePrivateNumbers(
            private_value=int.from_bytes(d, "big"),
            public_numbers=public_numbers,
        )
        return cls(private_numbers.private_key())

    def to_private_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, EllipticCurvePrivateKey):
            raise ValueError("The key is public")
        value = key.private_numbers().private_value
        return value.to_bytes((key.key_size + 7) // 8, "big")

    def to_public_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, EllipticCurvePublicKey):
            raise ValueError("The key is private")
        return key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.UncompressedPoint,
        )


class X25519Key(KEMKeyInterface):
    def __init__(self, key: Union[X25519PrivateKey, X25519PublicKey]) -> None:
        super().__init__(key)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> "X25519Key":
        if jwk.get("kty") != "OKP":
            raise ValueError(f"kty is not OKP: {jwk.get('kty')}.")
        if jwk.get("crv") != "X25519":
            raise ValueError(f"Unknown crv: {jwk.get('crv')}.")
        if "x" not in jwk:
            raise ValueError("x is required for X25519 JWK")
        x = base64url_decode(jwk["x"])
        if len(x) != 32:
            raise ValueError("x must be 32 bytes for X25519")
        if "d" not in jwk:
            return cls(x25519.X25519PublicKey.from_public_bytes(x))
        d = base64url_decode(jwk["d"])
        if len(d) != 32:
            raise ValueError("d must be 32 bytes for X25519")
        return cls(x25519.X25519PrivateKey.from_private_bytes(d))

    def to_private_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, X25519PrivateKey):
            raise ValueError("The key is public")
        return key.private_bytes_raw()

    def to_public_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, X25519PublicKey):
            raise ValueError("The key is private")
        return key.public_bytes_raw()


class X448Key(KEMKeyInterface):
    def __init__(self, key: Union[X448PrivateKey, X448PublicKey]) -> None:
        super().__init__(key)

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> "X448Key":
        if jwk.get("kty") != "OKP":
            raise ValueError(f"kty is not OKP: {jwk.get('kty')}.")
        if jwk.get("crv") != "X448":
            raise ValueError(f"Unknown crv: {jwk.get('crv')}.")
        if "x" not in jwk:
            raise ValueError("x is required for X448 JWK")
        x = base64url_decode(jwk["x"])
        if len(x) != 56:
            raise ValueError("x must be 56 bytes for X448")
        if "d" not in jwk:
            return cls(x448.X448PublicKey.from_public_bytes(x))
        d = base64url_decode(jwk["d"])
        if len(d) != 56:
            raise ValueError("d must be 56 bytes for X448")
        return cls(x448.X448PrivateKey.from_private_bytes(d))

    def to_private_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, X448PrivateKey):
            raise ValueError("The key is public")
        return key.private_bytes_raw()

    def to_public_bytes(self) -> bytes:
        key = self.raw
        if not isinstance(key, X448PublicKey):
            raise ValueError("The key is private")
        return key.public_bytes_raw()


class KEMKey:
    @classmethod
    def from_pyca_cryptography_key(cls, key: RawKEMKey) -> KEMKeyInterface:
        if isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
            return ECKey(key)
        if isinstance(key, (X25519PrivateKey, X25519PublicKey)):
            return X25519Key(key)
        if isinstance(key, (X448PrivateKey, X448PublicKey)):
            return X448Key(key)
        raise ValueError("Unsupported or unknown key")

    @classmethod
    def from_jwk(cls, data: Union[bytes, str, dict[str, Any]]) -> KEMKeyInterface:
        jwk: dict[str, Any] = json.loads(data) if not isinstance(data, dict) else data
        kty = jwk.get("kty")
        if kty not in _SUPPORTED_JWK_KTYS:
            raise ValueError(f"Unknown kty: {kty}.")
        if kty == "EC":
            return ECKey.from_jwk(jwk)
        crv = jwk.get("crv")
        if crv == "X25519":
            return X25519Key.from_jwk(jwk)
        if crv == "X448":
            return X448Key.from_jwk(jwk)
        raise ValueError(f"Unsupported or unknown crv: {crv}.")

    @classmethod
    def from_pem(cls, data: Union[bytes, str]) -> KEMKeyInterface:
        pem_data = data.encode("utf-8") if isinstance(data, str) else data
        pem_text = pem_data.decode("utf-8")

        if "BEGIN PUBLIC" in pem_text:
            public_key_obj = load_pem_public_key(pem_data)
            return cls.from_pyca_cryptography_key(cast(RawKEMKey, public_key_obj))
        if "BEGIN PRIVATE" in pem_text or "BEGIN EC PRIVATE" in pem_text:
            private_key_obj = load_pem_private_key(pem_data, password=None)
            return cls.from_pyca_cryptography_key(cast(RawKEMKey, private_key_obj))
        raise ValueError("Failed to decode PEM")
