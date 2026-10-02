from hypothesis import given, settings
from hypothesis import strategies as st

from rfc9180.constants import AEADID, AEAD_PARAMS, KDFID, KDF_PARAMS, KEMID, KEM_PARAMS
from rfc9180.exceptions import (
    DecapError,
    DeriveKeyPairError,
    DeserializeError,
    EncapError,
    HPKEError,
    MessageLimitReachedError,
    OpenError,
    ValidationError,
)
from rfc9180.types import KEMKey, KEMPrivateKey, KEMPublicKey


@given(raw=st.integers(min_value=0, max_value=0xFFFF))
@settings(max_examples=100)
def test_kemid_mapping_and_params(raw: int) -> None:
    try:
        kid = KEMID(raw)
    except ValueError:
        return
    assert kid in KEM_PARAMS
    params = KEM_PARAMS[kid]
    assert params["Nsecret"] > 0
    assert params["Nenc"] > 0
    assert params["Npk"] > 0
    assert params["Nsk"] > 0
    assert params["Ndh"] > 0


@given(raw=st.integers(min_value=0, max_value=0xFFFF))
@settings(max_examples=100)
def test_kdfid_mapping_and_params(raw: int) -> None:
    try:
        kid = KDFID(raw)
    except ValueError:
        return
    assert kid in KDF_PARAMS
    params = KDF_PARAMS[kid]
    assert params["Nh"] > 0


@given(raw=st.integers(min_value=0, max_value=0xFFFF))
@settings(max_examples=100)
def test_aeadid_mapping_and_params(raw: int) -> None:
    try:
        aid = AEADID(raw)
    except ValueError:
        return
    assert aid in AEAD_PARAMS
    params = AEAD_PARAMS[aid]
    assert params["Nk"] >= 0
    assert params["Nn"] >= 0
    assert params["Nt"] >= 0


def test_types_aliases_include_expected() -> None:
    assert KEMPublicKey.__args__  # type: ignore[attr-defined]
    assert KEMPrivateKey.__args__  # type: ignore[attr-defined]
    assert KEMKey.__args__  # type: ignore[attr-defined]


def test_exceptions_inherit_from_hpkeerror() -> None:
    assert issubclass(ValidationError, HPKEError)
    assert issubclass(DeserializeError, HPKEError)
    assert issubclass(EncapError, HPKEError)
    assert issubclass(DecapError, HPKEError)
    assert issubclass(OpenError, HPKEError)
    assert issubclass(MessageLimitReachedError, HPKEError)
    assert issubclass(DeriveKeyPairError, HPKEError)

