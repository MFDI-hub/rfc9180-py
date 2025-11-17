from typing import Tuple

from .context import ContextSender, ContextRecipient
from .primitives.kem import KEMBase
from .primitives.kdf import KDFBase
from .primitives.aead import AEADBase
from .constants import HPKEMode, AEADID
from .utils import I2OSP, concat


class HPKESetup:
    """
    HPKE Setup functions (RFC 9180 §5.1).
    """

    def __init__(self, kem: KEMBase, kdf: KDFBase, aead: AEADBase):
        self.kem = kem
        self.kdf = kdf
        self.aead = aead
        self.suite_id = concat(
            b"HPKE",
            I2OSP(kem.kem_id, 2),
            I2OSP(kdf.kdf_id, 2),
            I2OSP(aead.aead_id, 2),
        )

    def verify_psk_inputs(self, mode: HPKEMode, psk: bytes, psk_id: bytes):
        got_psk = len(psk) > 0
        got_psk_id = len(psk_id) > 0
        if got_psk != got_psk_id:
            raise ValueError("Inconsistent PSK inputs")
        if got_psk and mode in (HPKEMode.MODE_BASE, HPKEMode.MODE_AUTH):
            raise ValueError("PSK input provided when not needed")
        if (not got_psk) and mode in (HPKEMode.MODE_PSK, HPKEMode.MODE_AUTH_PSK):
            raise ValueError("Missing required PSK input")

    def key_schedule(self, role: str, mode: HPKEMode, shared_secret: bytes, info: bytes, psk: bytes, psk_id: bytes):
        self.verify_psk_inputs(mode, psk, psk_id)
        psk_id_hash = self.kdf.labeled_extract(
            salt=b"",
            label="psk_id_hash",
            ikm=psk_id,
            suite_id=self.suite_id,
        )
        info_hash = self.kdf.labeled_extract(
            salt=b"",
            label="info_hash",
            ikm=info,
            suite_id=self.suite_id,
        )
        key_schedule_context = concat(
            I2OSP(mode, 1),
            psk_id_hash,
            info_hash,
        )
        secret = self.kdf.labeled_extract(
            salt=shared_secret,
            label="secret",
            ikm=psk,
            suite_id=self.suite_id,
        )
        key = b""
        base_nonce = b""
        if self.aead.aead_id != AEADID.EXPORT_ONLY:
            key = self.kdf.labeled_expand(
                prk=secret,
                label="key",
                info=key_schedule_context,
                L=self.aead.Nk,
                suite_id=self.suite_id,
            )
            base_nonce = self.kdf.labeled_expand(
                prk=secret,
                label="base_nonce",
                info=key_schedule_context,
                L=self.aead.Nn,
                suite_id=self.suite_id,
            )
        exporter_secret = self.kdf.labeled_expand(
            prk=secret,
            label="exp",
            info=key_schedule_context,
            L=self.kdf.Nh,
            suite_id=self.suite_id,
        )
        ctx_args = dict(
            aead=self.aead,
            kdf=self.kdf,
            key=key,
            base_nonce=base_nonce,
            exporter_secret=exporter_secret,
            suite_id=self.suite_id,
        )
        if role == 'S':
            return ContextSender(**ctx_args)
        return ContextRecipient(**ctx_args)

    def setup_base_sender(self, pkR, info: bytes) -> Tuple[bytes, ContextSender]:
        shared_secret, enc = self.kem.encap(pkR)
        ctx = self.key_schedule('S', HPKEMode.MODE_BASE, shared_secret, info, psk=b"", psk_id=b"")
        return enc, ctx

    def setup_base_recipient(self, enc: bytes, skR, info: bytes) -> ContextRecipient:
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule('R', HPKEMode.MODE_BASE, shared_secret, info, psk=b"", psk_id=b"")

    def setup_psk_sender(self, pkR, info: bytes, psk: bytes, psk_id: bytes) -> Tuple[bytes, ContextSender]:
        if len(psk) < 32:
            raise ValueError("PSK must have at least 32 bytes of entropy")
        shared_secret, enc = self.kem.encap(pkR)
        ctx = self.key_schedule('S', HPKEMode.MODE_PSK, shared_secret, info, psk=psk, psk_id=psk_id)
        return enc, ctx

    def setup_psk_recipient(self, enc: bytes, skR, info: bytes, psk: bytes, psk_id: bytes) -> ContextRecipient:
        if len(psk) < 32:
            raise ValueError("PSK must have at least 32 bytes of entropy")
        shared_secret = self.kem.decap(enc, skR)
        return self.key_schedule('R', HPKEMode.MODE_PSK, shared_secret, info, psk=psk, psk_id=psk_id)

    def setup_auth_sender(self, pkR, info: bytes, skS) -> Tuple[bytes, ContextSender]:
        shared_secret, enc = self.kem.auth_encap(pkR, skS)
        ctx = self.key_schedule('S', HPKEMode.MODE_AUTH, shared_secret, info, psk=b"", psk_id=b"")
        return enc, ctx

    def setup_auth_recipient(self, enc: bytes, skR, info: bytes, pkS) -> ContextRecipient:
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule('R', HPKEMode.MODE_AUTH, shared_secret, info, psk=b"", psk_id=b"")

    def setup_auth_psk_sender(self, pkR, info: bytes, psk: bytes, psk_id: bytes, skS) -> Tuple[bytes, ContextSender]:
        if len(psk) < 32:
            raise ValueError("PSK must have at least 32 bytes of entropy")
        shared_secret, enc = self.kem.auth_encap(pkR, skS)
        ctx = self.key_schedule('S', HPKEMode.MODE_AUTH_PSK, shared_secret, info, psk=psk, psk_id=psk_id)
        return enc, ctx

    def setup_auth_psk_recipient(self, enc: bytes, skR, info: bytes, psk: bytes, psk_id: bytes, pkS) -> ContextRecipient:
        if len(psk) < 32:
            raise ValueError("PSK must have at least 32 bytes of entropy")
        shared_secret = self.kem.auth_decap(enc, skR, pkS)
        return self.key_schedule('R', HPKEMode.MODE_AUTH_PSK, shared_secret, info, psk=psk, psk_id=psk_id)


