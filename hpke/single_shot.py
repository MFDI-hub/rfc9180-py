from typing import Tuple

from .setup import HPKESetup


class HPKESingleShot:
    """
    Single-shot HPKE APIs (RFC 9180 §6).
    """

    def __init__(self, setup: HPKESetup):
        self.setup = setup

    # Base Mode
    def seal_base(self, pkR, info: bytes, aad: bytes, pt: bytes) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_base_sender(pkR, info)
        return enc, ctx.seal(aad, pt)

    def open_base(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes) -> bytes:
        ctx = self.setup.setup_base_recipient(enc, skR, info)
        return ctx.open(aad, ct)

    # PSK Mode
    def seal_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_psk_sender(pkR, info, psk, psk_id)
        return enc, ctx.seal(aad, pt)

    def open_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes) -> bytes:
        ctx = self.setup.setup_psk_recipient(enc, skR, info, psk, psk_id)
        return ctx.open(aad, ct)

    # Auth Mode
    def seal_auth(self, pkR, info: bytes, aad: bytes, pt: bytes, skS) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_auth_sender(pkR, info, skS)
        return enc, ctx.seal(aad, pt)

    def open_auth(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, pkS) -> bytes:
        ctx = self.setup.setup_auth_recipient(enc, skR, info, pkS)
        return ctx.open(aad, ct)

    # AuthPSK Mode
    def seal_auth_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes, skS) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_auth_psk_sender(pkR, info, psk, psk_id, skS)
        return enc, ctx.seal(aad, pt)

    def open_auth_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes, pkS) -> bytes:
        ctx = self.setup.setup_auth_psk_recipient(enc, skR, info, psk, psk_id, pkS)
        return ctx.open(aad, ct)

    # Export-only helpers
    def send_export_base(self, pkR, info: bytes, exporter_context: bytes, L: int) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_base_sender(pkR, info)
        return enc, ctx.export(exporter_context, L)

    def receive_export_base(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int) -> bytes:
        ctx = self.setup.setup_base_recipient(enc, skR, info)
        return ctx.export(exporter_context, L)

    def send_export_psk(self, pkR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_psk_sender(pkR, info, psk, psk_id)
        return enc, ctx.export(exporter_context, L)

    def receive_export_psk(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes) -> bytes:
        ctx = self.setup.setup_psk_recipient(enc, skR, info, psk, psk_id)
        return ctx.export(exporter_context, L)

    def send_export_auth(self, pkR, info: bytes, exporter_context: bytes, L: int, skS) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_auth_sender(pkR, info, skS)
        return enc, ctx.export(exporter_context, L)

    def receive_export_auth(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, pkS) -> bytes:
        ctx = self.setup.setup_auth_recipient(enc, skR, info, pkS)
        return ctx.export(exporter_context, L)

    def send_export_auth_psk(self, pkR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes, skS) -> Tuple[bytes, bytes]:
        enc, ctx = self.setup.setup_auth_psk_sender(pkR, info, psk, psk_id, skS)
        return enc, ctx.export(exporter_context, L)

    def receive_export_auth_psk(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes, pkS) -> bytes:
        ctx = self.setup.setup_auth_psk_recipient(enc, skR, info, psk, psk_id, pkS)
        return ctx.export(exporter_context, L)


