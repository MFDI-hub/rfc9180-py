from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import KDFID
from rfc9180.primitives.kdf import KDFBase


def kdf_strategies() -> st.SearchStrategy[KDFBase]:
    return st.sampled_from(
        [
            KDFBase(KDFID.HKDF_SHA256),
            KDFBase(KDFID.HKDF_SHA384),
            KDFBase(KDFID.HKDF_SHA512),
        ]
    )


@given(
    kdf=kdf_strategies(),
    salt=st.binary(min_size=0, max_size=64),
    ikm=st.binary(min_size=0, max_size=256),
    info=st.binary(min_size=0, max_size=128),
    L=st.integers(min_value=0, max_value=1024),
)
@settings(max_examples=100)
def test_kdf_extract_expand_properties(
    kdf: KDFBase, salt: bytes, ikm: bytes, info: bytes, L: int
) -> None:
    prk = kdf.extract(salt, ikm)
    assert len(prk) == kdf.Nh
    if L > 255 * kdf.Nh:
        from pytest import raises

        with raises(ValueError):
            kdf.expand(prk, info, L)
        return
    okm1 = kdf.expand(prk, info, L)
    okm2 = kdf.expand(prk, info, L)
    assert len(okm1) == L
    assert okm1 == okm2


@given(
    kdf=kdf_strategies(),
    label=st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), max_size=16),
    info=st.binary(min_size=0, max_size=64),
    suite_id=st.binary(min_size=4, max_size=16),
    L=st.integers(min_value=0, max_value=512),
)
@settings(max_examples=100)
def test_kdf_labeled_extract_expand_domain_separation(
    kdf: KDFBase, label: str, info: bytes, suite_id: bytes, L: int
) -> None:
    ikm = b"input key material"
    prk = kdf.labeled_extract(b"", label, ikm, suite_id)
    assert len(prk) == kdf.Nh
    if L > 255 * kdf.Nh:
        from pytest import raises

        with raises(ValueError):
            kdf.labeled_expand(prk, "sec", info, L, suite_id)
        return
    okm = kdf.labeled_expand(prk, "sec", info, L, suite_id)
    assert len(okm) == L

