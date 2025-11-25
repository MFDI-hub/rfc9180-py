from rfc9180.constants import KDFID
from rfc9180.primitives.kdf import KDFBase

# RFC 5869 - Test Case 1 (SHA-256)
IKM = bytes.fromhex("0b" * 22)
SALT = bytes.fromhex("000102030405060708090a0b0c")
INFO = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
L = 42
PRK_EXPECTED = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba63"
    "90b6c73bb50f9c3122ec844ad7c2b3e5"
)
OKM_EXPECTED = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def test_hkdf_extract_and_expand_sha256():
    kdf = KDFBase(KDFID.HKDF_SHA256)
    prk = kdf.extract(SALT, IKM)
    assert prk == PRK_EXPECTED
    okm = kdf.expand(prk, INFO, L)
    assert okm == OKM_EXPECTED


