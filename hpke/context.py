from typing import Literal

from .exceptions import MessageLimitReachedError
from .primitives.aead import AEADBase
from .primitives.kdf import KDFBase
from .utils import I2OSP, xor_bytes

Role = Literal['S', 'R']


class Context:
    """
    HPKE Encryption Context (RFC 9180 §5.2).

    Manages the encryption/decryption state for HPKE operations, including
    sequence number tracking and key export functionality.

    Parameters
    ----------
    role : Role
        Context role ('S' for sender, 'R' for recipient).
    aead : AEADBase
        AEAD algorithm instance.
    kdf : KDFBase
        KDF algorithm instance.
    key : bytes
        AEAD encryption key.
    base_nonce : bytes
        Base nonce for nonce generation.
    exporter_secret : bytes
        Secret for key export operations.
    suite_id : bytes
        HPKE suite identifier.

    Attributes
    ----------
    role : Role
        Context role.
    aead : AEADBase
        AEAD algorithm instance.
    kdf : KDFBase
        KDF algorithm instance.
    key : bytes
        AEAD encryption key.
    base_nonce : bytes
        Base nonce for nonce generation.
    exporter_secret : bytes
        Secret for key export operations.
    suite_id : bytes
        HPKE suite identifier.
    seq : int
        Current sequence number.
    """

    def __init__(
        self,
        role: Role,
        aead: AEADBase,
        kdf: KDFBase,
        key: bytes,
        base_nonce: bytes,
        exporter_secret: bytes,
        suite_id: bytes,
    ):
        self.role = role
        self.aead = aead
        self.kdf = kdf
        self.key = key
        self.base_nonce = base_nonce
        self.exporter_secret = exporter_secret
        self.suite_id = suite_id
        self.seq = 0

    def compute_nonce(self, seq: int) -> bytes:
        """
        Compute nonce for a given sequence number.

        Parameters
        ----------
        seq : int
            Sequence number.

        Returns
        -------
        bytes
            Computed nonce.
        """
        seq_bytes = I2OSP(seq, self.aead.Nn)
        return xor_bytes(self.base_nonce, seq_bytes)

    def increment_seq(self):
        """
        Increment the sequence number.

        Raises
        ------
        MessageLimitReachedError
            If sequence number would overflow.
        """
        if self.seq >= self.aead.max_seq:
            raise MessageLimitReachedError("Sequence number overflow")
        self.seq += 1

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        """
        Seal (encrypt) a message.

        Parameters
        ----------
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.

        Returns
        -------
        bytes
            Ciphertext.

        Raises
        ------
        ValueError
            If context is not a sender context.
        MessageLimitReachedError
            If sequence number would overflow.
        """
        if self.role != 'S':
            raise ValueError("Only sender context can seal")
        nonce = self.compute_nonce(self.seq)
        ct = self.aead.seal(self.key, nonce, aad, pt)
        self.increment_seq()
        return ct

    def open(self, aad: bytes, ct: bytes) -> bytes:
        """
        Open (decrypt) a message.

        Parameters
        ----------
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
        ValueError
            If context is not a recipient context.
        OpenError
            If decryption fails.
        MessageLimitReachedError
            If sequence number would overflow.
        """
        if self.role != 'R':
            raise ValueError("Only recipient context can open")
        nonce = self.compute_nonce(self.seq)
        pt = self.aead.open(self.key, nonce, aad, ct)
        self.increment_seq()
        return pt

    def export(self, exporter_context: bytes, L: int) -> bytes:
        """
        Export a secret value.

        Parameters
        ----------
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.

        Returns
        -------
        bytes
            Exported secret.

        Raises
        ------
        ValueError
            If export length exceeds maximum.
        """
        if L > 255 * self.kdf.Nh:
            raise ValueError(f"Export length {L} exceeds maximum {255 * self.kdf.Nh}")
        return self.kdf.labeled_expand(
            prk=self.exporter_secret,
            label="sec",
            info=exporter_context,
            L=L,
            suite_id=self.suite_id,
        )


class ContextSender(Context):
    """
    Sender encryption context.

    A specialized Context for senders that can only seal (encrypt) messages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__('S', *args, **kwargs)


class ContextRecipient(Context):
    """
    Recipient decryption context.

    A specialized Context for recipients that can only open (decrypt) messages.
    """
    def __init__(self, *args, **kwargs):
        super().__init__('R', *args, **kwargs)


