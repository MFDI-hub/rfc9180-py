from typing import Literal

from .exceptions import MessageLimitReachedError
from .primitives.aead import AEADBase
from .primitives.kdf import KDFBase
from .utils import I2OSP, xor_bytes

Role = Literal['S', 'R']


class Context:
    """
    HPKE Encryption Context (RFC 9180 §5.2)
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
        seq_bytes = I2OSP(seq, self.aead.Nn)
        return xor_bytes(self.base_nonce, seq_bytes)

    def increment_seq(self):
        if self.seq >= self.aead.max_seq:
            raise MessageLimitReachedError("Sequence number overflow")
        self.seq += 1

    def seal(self, aad: bytes, pt: bytes) -> bytes:
        if self.role != 'S':
            raise ValueError("Only sender context can seal")
        nonce = self.compute_nonce(self.seq)
        ct = self.aead.seal(self.key, nonce, aad, pt)
        self.increment_seq()
        return ct

    def open(self, aad: bytes, ct: bytes) -> bytes:
        if self.role != 'R':
            raise ValueError("Only recipient context can open")
        nonce = self.compute_nonce(self.seq)
        pt = self.aead.open(self.key, nonce, aad, ct)
        self.increment_seq()
        return pt

    def export(self, exporter_context: bytes, L: int) -> bytes:
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
    def __init__(self, *args, **kwargs):
        super().__init__('S', *args, **kwargs)


class ContextRecipient(Context):
    def __init__(self, *args, **kwargs):
        super().__init__('R', *args, **kwargs)


