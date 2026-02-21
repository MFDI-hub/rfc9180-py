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
        # RFC 9180 §7.2.1 input-length accounting constants.
        self._version_label_len = len(b"HPKE-v1")
        self._extract_hash_block_size = self._get_hash_block_size()
        self._max_hash_input_len = self._get_max_hash_input_len()

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

    def _get_hash_block_size(self) -> int:
        """
        Return the underlying hash block size (Nb) in bytes.
        """
        mapping = {
            KDFID.HKDF_SHA256: 64,
            KDFID.HKDF_SHA384: 128,
            KDFID.HKDF_SHA512: 128,
        }
        return mapping[self.kdf_id]

    def _get_max_hash_input_len(self) -> int:
        """
        Return the maximum hash input length in bytes.

        SHA-256 allows messages of at most (2^64 - 1) bits => 2^61 - 1 bytes.
        SHA-384/SHA-512 allow messages of at most (2^128 - 1) bits => 2^125 - 1 bytes.
        """
        if self.kdf_id == KDFID.HKDF_SHA256:
            return (1 << 61) - 1
        return (1 << 125) - 1

    def _max_labeled_extract_ikm_len(self, label_len: int, suite_id_len: int) -> int:
        """
        RFC 9180 §7.2.1 limit for the ikm argument to LabeledExtract().
        """
        return (
            self._max_hash_input_len
            - self._extract_hash_block_size
            - self._version_label_len
            - suite_id_len
            - label_len
        )

    def _max_labeled_expand_info_len(self, label_len: int, suite_id_len: int) -> int:
        """
        RFC 9180 §7.2.1 limit for the info argument to LabeledExpand().
        """
        return (
            self._max_hash_input_len
            - self._extract_hash_block_size
            - self.Nh
            - self._version_label_len
            - suite_id_len
            - label_len
            - 2  # I2OSP(L, 2)
            - 1  # HKDF-Expand block counter octet
        )

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
        label_bytes = label.encode('ascii')
        max_ikm_len = self._max_labeled_extract_ikm_len(len(label_bytes), len(suite_id))
        if len(ikm) > max_ikm_len:
            raise ValueError(
                f"LabeledExtract ikm length {len(ikm)} exceeds maximum {max_ikm_len}"
            )

        labeled_ikm = concat(
            b"HPKE-v1",
            suite_id,
            label_bytes,
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
        label_bytes = label.encode('ascii')
        max_info_len = self._max_labeled_expand_info_len(len(label_bytes), len(suite_id))
        if len(info) > max_info_len:
            raise ValueError(
                f"LabeledExpand info length {len(info)} exceeds maximum {max_info_len}"
            )

        labeled_info = concat(
            I2OSP(L, 2),
            b"HPKE-v1",
            suite_id,
            label_bytes,
            info,
        )
        return self.expand(prk, labeled_info, L)


