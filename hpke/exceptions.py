class HPKEError(Exception):
    """
    Base exception for HPKE errors.

    All HPKE-specific exceptions inherit from this class.
    """
    pass


class ValidationError(HPKEError):
    """
    KEM input/output validation failure.

    Raised when KEM operations fail validation checks, such as
    all-zero DH outputs.
    """
    pass


class DeserializeError(HPKEError):
    """
    Key deserialization failure.

    Raised when key deserialization fails due to invalid format
    or length.
    """
    pass


class EncapError(HPKEError):
    """
    Encapsulation failure.

    Raised when key encapsulation operations fail.
    """
    pass


class DecapError(HPKEError):
    """
    Decapsulation failure.

    Raised when key decapsulation operations fail.
    """
    pass


class OpenError(HPKEError):
    """
    AEAD decryption failure.

    Raised when AEAD decryption operations fail, typically due to
    authentication failure or invalid ciphertext.
    """
    pass


class MessageLimitReachedError(HPKEError):
    """
    Sequence number overflow.

    Raised when the sequence number exceeds the maximum allowed
    value for the AEAD algorithm.
    """
    pass


class DeriveKeyPairError(HPKEError):
    """
    Key pair derivation failure.

    Raised when key pair derivation fails, such as when rejection
    sampling exceeds the maximum number of iterations.
    """
    pass


