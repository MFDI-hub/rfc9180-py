from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..constants import KDF_PARAMS, KDFID
from ..utils import I2OSP, concat


class KDFBase:
    """
    Base class for KDF implementations (HKDF variants).

    Provides key derivation functions based on HKDF (RFC 5869) with
    HPKE-specific labeled operations (RFC 9180 §4).

    Parameters
    ----------
    kdf_id : KDFID
        KDF algorithm identifier.

    Attributes
    ----------
    kdf_id : KDFID
        KDF algorithm identifier.
    Nh : int
        Hash output length in bytes.
    hash_algorithm
        Hash algorithm instance.
    """

    def __init__(self, kdf_id: KDFID):
        self.kdf_id = kdf_id
        self.Nh = KDF_PARAMS[self.kdf_id]['Nh']
        self.hash_algorithm = self._get_hash_algorithm()

    def _get_hash_algorithm(self):
        """
        Get hash algorithm for the KDF.

        Returns
        -------
        HashAlgorithm
            Hash algorithm instance.
        """
        mapping = {
            KDFID.HKDF_SHA256: hashes.SHA256(),
            KDFID.HKDF_SHA384: hashes.SHA384(),
            KDFID.HKDF_SHA512: hashes.SHA512(),
        }
        return mapping[self.kdf_id]

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        HKDF-Extract (RFC 5869).

        Parameters
        ----------
        salt : bytes
            Salt value (empty salt is replaced with zero bytes).
        ikm : bytes
            Input key material.

        Returns
        -------
        bytes
            Pseudorandom key (PRK).
        """
        if not salt:
            salt = b'\x00' * self.Nh

        h = HMAC(salt, self.hash_algorithm)
        h.update(ikm)
        return h.finalize()

    def expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        HKDF-Expand (RFC 5869).

        Parameters
        ----------
        prk : bytes
            Pseudorandom key.
        info : bytes
            Application-specific information.
        L : int
            Desired output length in bytes.

        Returns
        -------
        bytes
            Output keying material.

        Raises
        ------
        ValueError
            If requested length exceeds maximum (255 * Nh).
        """
        if L > 255 * self.Nh:
            raise ValueError(f"Requested length {L} exceeds maximum {255 * self.Nh}")

        hkdf_expand = HKDFExpand(
            algorithm=self.hash_algorithm,
            length=L,
            info=info,
        )
        return hkdf_expand.derive(prk)

    def labeled_extract(self, salt: bytes, label: str, ikm: bytes, suite_id: bytes) -> bytes:
        """
        LabeledExtract from RFC 9180 §4.

        Parameters
        ----------
        salt : bytes
            Salt value.
        label : str
            Label string.
        ikm : bytes
            Input key material.
        suite_id : bytes
            HPKE suite identifier.

        Returns
        -------
        bytes
            Pseudorandom key (PRK).
        """
        labeled_ikm = concat(
            b"HPKE-v1",
            suite_id,
            label.encode('ascii'),
            ikm,
        )
        return self.extract(salt, labeled_ikm)

    def labeled_expand(self, prk: bytes, label: str, info: bytes, L: int, suite_id: bytes) -> bytes:
        """
        LabeledExpand from RFC 9180 §4.

        Parameters
        ----------
        prk : bytes
            Pseudorandom key.
        label : str
            Label string.
        info : bytes
            Application-specific information.
        L : int
            Desired output length in bytes.
        suite_id : bytes
            HPKE suite identifier.

        Returns
        -------
        bytes
            Output keying material.

        Raises
        ------
        ValueError
            If requested length exceeds maximum (255 * Nh).
        """
        labeled_info = concat(
            I2OSP(L, 2),
            b"HPKE-v1",
            suite_id,
            label.encode('ascii'),
            info,
        )
        return self.expand(prk, labeled_info, L)


