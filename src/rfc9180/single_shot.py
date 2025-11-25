from typing import Tuple

from .setup import HPKESetup


class HPKESingleShot:
    """
    Single-shot HPKE APIs (RFC 9180 §6).

    Provides convenient single-shot encryption/decryption operations that
    combine setup and encryption/decryption in one call.

    Parameters
    ----------
    setup : HPKESetup
        HPKE setup instance for context creation.

    Attributes
    ----------
    setup : HPKESetup
        HPKE setup instance.
    """

    def __init__(self, setup: HPKESetup):
        self.setup = setup

    # Base Mode
    def seal_base(self, pkR, info: bytes, aad: bytes, pt: bytes) -> Tuple[bytes, bytes]:
        """
        Seal (encrypt) a message using Base mode.

        Parameters
        ----------
        pkR : Key Object
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
        enc, ctx = self.setup.setup_base_sender(pkR, info)
        return enc, ctx.seal(aad, pt)

    def open_base(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes) -> bytes:
        """
        Open (decrypt) a message using Base mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
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
        ctx = self.setup.setup_base_recipient(enc, skR, info)
        return ctx.open(aad, ct)

    # PSK Mode
    def seal_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes) -> Tuple[bytes, bytes]:
        """
        Seal (encrypt) a message using PSK mode.

        Parameters
        ----------
        pkR : Key Object
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
        enc, ctx = self.setup.setup_psk_sender(pkR, info, psk, psk_id)
        return enc, ctx.seal(aad, pt)

    def open_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes) -> bytes:
        """
        Open (decrypt) a message using PSK mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
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
        ctx = self.setup.setup_psk_recipient(enc, skR, info, psk, psk_id)
        return ctx.open(aad, ct)

    # Auth Mode
    def seal_auth(self, pkR, info: bytes, aad: bytes, pt: bytes, skS) -> Tuple[bytes, bytes]:
        """
        Seal (encrypt) a message using Auth mode.

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        pt : bytes
            Plaintext to encrypt.
        skS : Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, ciphertext).
        """
        enc, ctx = self.setup.setup_auth_sender(pkR, info, skS)
        return enc, ctx.seal(aad, pt)

    def open_auth(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, pkS) -> bytes:
        """
        Open (decrypt) a message using Auth mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        aad : bytes
            Additional authenticated data.
        ct : bytes
            Ciphertext to decrypt.
        pkS : Key Object
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
        ctx = self.setup.setup_auth_recipient(enc, skR, info, pkS)
        return ctx.open(aad, ct)

    # AuthPSK Mode
    def seal_auth_psk(self, pkR, info: bytes, aad: bytes, pt: bytes, psk: bytes, psk_id: bytes, skS) -> Tuple[bytes, bytes]:
        """
        Seal (encrypt) a message using AuthPSK mode.

        Parameters
        ----------
        pkR : Key Object
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
        skS : Key Object
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
        enc, ctx = self.setup.setup_auth_psk_sender(pkR, info, psk, psk_id, skS)
        return enc, ctx.seal(aad, pt)

    def open_auth_psk(self, enc: bytes, skR, info: bytes, aad: bytes, ct: bytes, psk: bytes, psk_id: bytes, pkS) -> bytes:
        """
        Open (decrypt) a message using AuthPSK mode.

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
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
        pkS : Key Object
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
        ctx = self.setup.setup_auth_psk_recipient(enc, skR, info, psk, psk_id, pkS)
        return ctx.open(aad, ct)

    # Export-only helpers
    def send_export_base(self, pkR, info: bytes, exporter_context: bytes, L: int) -> Tuple[bytes, bytes]:
        """
        Export a secret using Base mode (sender side).

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, exported secret).
        """
        enc, ctx = self.setup.setup_base_sender(pkR, info)
        return enc, ctx.export(exporter_context, L)

    def receive_export_base(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int) -> bytes:
        """
        Export a secret using Base mode (recipient side).

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.

        Returns
        -------
        bytes
            Exported secret.
        """
        ctx = self.setup.setup_base_recipient(enc, skR, info)
        return ctx.export(exporter_context, L)

    def send_export_psk(self, pkR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes) -> Tuple[bytes, bytes]:
        """
        Export a secret using PSK mode (sender side).

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, exported secret).

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        enc, ctx = self.setup.setup_psk_sender(pkR, info, psk, psk_id)
        return enc, ctx.export(exporter_context, L)

    def receive_export_psk(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes) -> bytes:
        """
        Export a secret using PSK mode (recipient side).

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.

        Returns
        -------
        bytes
            Exported secret.

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        ctx = self.setup.setup_psk_recipient(enc, skR, info, psk, psk_id)
        return ctx.export(exporter_context, L)

    def send_export_auth(self, pkR, info: bytes, exporter_context: bytes, L: int, skS) -> Tuple[bytes, bytes]:
        """
        Export a secret using Auth mode (sender side).

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        skS : Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, exported secret).
        """
        enc, ctx = self.setup.setup_auth_sender(pkR, info, skS)
        return enc, ctx.export(exporter_context, L)

    def receive_export_auth(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, pkS) -> bytes:
        """
        Export a secret using Auth mode (recipient side).

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        pkS : Key Object
            Sender's public key.

        Returns
        -------
        bytes
            Exported secret.
        """
        ctx = self.setup.setup_auth_recipient(enc, skR, info, pkS)
        return ctx.export(exporter_context, L)

    def send_export_auth_psk(self, pkR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes, skS) -> Tuple[bytes, bytes]:
        """
        Export a secret using AuthPSK mode (sender side).

        Parameters
        ----------
        pkR : Key Object
            Recipient's public key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.
        skS : Key Object
            Sender's private key.

        Returns
        -------
        tuple
            Tuple of (encapsulated key, exported secret).

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        enc, ctx = self.setup.setup_auth_psk_sender(pkR, info, psk, psk_id, skS)
        return enc, ctx.export(exporter_context, L)

    def receive_export_auth_psk(self, enc: bytes, skR, info: bytes, exporter_context: bytes, L: int, psk: bytes, psk_id: bytes, pkS) -> bytes:
        """
        Export a secret using AuthPSK mode (recipient side).

        Parameters
        ----------
        enc : bytes
            Encapsulated public key.
        skR : Key Object
            Recipient's private key.
        info : bytes
            Application-supplied information.
        exporter_context : bytes
            Exporter context.
        L : int
            Length of exported secret in bytes.
        psk : bytes
            Pre-shared key (must have at least 32 bytes of entropy).
        psk_id : bytes
            Pre-shared key identifier.
        pkS : Key Object
            Sender's public key.

        Returns
        -------
        bytes
            Exported secret.

        Raises
        ------
        ValueError
            If PSK has insufficient entropy.
        """
        ctx = self.setup.setup_auth_psk_recipient(enc, skR, info, psk, psk_id, pkS)
        return ctx.export(exporter_context, L)


