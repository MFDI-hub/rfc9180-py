from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ..constants import KDF_PARAMS, KDFID
from ..utils import I2OSP, concat


class KDFBase:
    """
    Base class for KDF implementations (HKDF variants).
    """

    def __init__(self, kdf_id: KDFID):
        self.kdf_id = kdf_id
        self.Nh = KDF_PARAMS[self.kdf_id]['Nh']
        self.hash_algorithm = self._get_hash_algorithm()

    def _get_hash_algorithm(self):
        mapping = {
            KDFID.HKDF_SHA256: hashes.SHA256(),
            KDFID.HKDF_SHA384: hashes.SHA384(),
            KDFID.HKDF_SHA512: hashes.SHA512(),
        }
        return mapping[self.kdf_id]

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        """
        HKDF-Extract (RFC 5869).
        """
        if not salt:
            salt = b'\x00' * self.Nh

        h = HMAC(salt, self.hash_algorithm)
        h.update(ikm)
        return h.finalize()

    def expand(self, prk: bytes, info: bytes, L: int) -> bytes:
        """
        HKDF-Expand (RFC 5869).
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
        """
        labeled_info = concat(
            I2OSP(L, 2),
            b"HPKE-v1",
            suite_id,
            label.encode('ascii'),
            info,
        )
        return self.expand(prk, labeled_info, L)


