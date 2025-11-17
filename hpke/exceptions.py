class HPKEError(Exception):
    """Base exception for HPKE errors."""
    pass


class ValidationError(HPKEError):
    """KEM input/output validation failure."""
    pass


class DeserializeError(HPKEError):
    """Key deserialization failure."""
    pass


class EncapError(HPKEError):
    """Encapsulation failure."""
    pass


class DecapError(HPKEError):
    """Decapsulation failure."""
    pass


class OpenError(HPKEError):
    """AEAD decryption failure."""
    pass


class MessageLimitReachedError(HPKEError):
    """Sequence number overflow."""
    pass


class DeriveKeyPairError(HPKEError):
    """Key pair derivation failure."""
    pass


