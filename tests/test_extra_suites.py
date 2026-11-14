"""Known answers for suites the official CFRG vector file does not cover.

The expected bytes were produced with an HKDF implementation written from
RFC 9180 using hashlib and hmac, plus cryptography only for the group
operation and the AEAD. They are pinned here so a later refactor cannot
change X448, HKDF-SHA384, or P-256 AuthPSK without a failing test.
"""

import json
import os

import pytest

from rfc9180.constants import AEADID, KDFID, HPKEMode
from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase
from rfc9180.primitives.kem import DHKEM_P256, DHKEM_X448, DHKEM_X25519
from rfc9180.setup import HPKESetup

_KEMS = {
    "DHKEM_X25519": DHKEM_X25519,
    "DHKEM_X448": DHKEM_X448,
    "DHKEM_P256": DHKEM_P256,
}
_KDFS = {
    "HKDF_SHA384": KDFID.HKDF_SHA384,
    "HKDF_SHA512": KDFID.HKDF_SHA512,
}
_AEADS = {
    "AES_128_GCM": AEADID.AES_128_GCM,
    "AES_256_GCM": AEADID.AES_256_GCM,
    "CHACHA20_POLY1305": AEADID.CHACHA20_POLY1305,
}
_MODES = {
    "BASE": HPKEMode.MODE_BASE,
    "AUTH_PSK": HPKEMode.MODE_AUTH_PSK,
}


def _load() -> list[dict]:
    path = os.path.join(os.path.dirname(__file__), "..", "vectors", "extra-suites.json")
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.mark.parametrize("vec", _load(), ids=lambda vec: vec["name"])
def test_extra_suite_known_answers(vec: dict) -> None:
    kem = _KEMS[vec["kem"]]()
    mode = _MODES[vec["mode"]]
    setup = HPKESetup(kem, KDFBase(_KDFS[vec["kdf"]]), AEADBase(_AEADS[vec["aead"]]))

    sk_r, pk_r = kem.derive_key_pair(bytes.fromhex(vec["ikmR"]))
    _sk_e, pk_e = kem.derive_key_pair(bytes.fromhex(vec["ikmE"]))
    enc = kem.serialize_public_key(pk_e)
    info = bytes.fromhex(vec["info"])
    psk = bytes.fromhex(vec["psk"]) if vec["psk"] else b""
    psk_id = bytes.fromhex(vec["psk_id"]) if vec["psk_id"] else b""

    assert kem.serialize_private_key(sk_r) == bytes.fromhex(vec["skRm"])
    assert kem.serialize_public_key(pk_r) == bytes.fromhex(vec["pkRm"])
    assert enc == bytes.fromhex(vec["enc"])

    if mode == HPKEMode.MODE_AUTH_PSK:
        _sk_s, pk_s = kem.derive_key_pair(bytes.fromhex(vec["ikmS"]))
        assert kem.serialize_public_key(pk_s) == bytes.fromhex(vec["pkSm"])
        shared = kem.auth_decap(enc, sk_r, pk_s)
    else:
        shared = kem.decap(enc, sk_r)
    assert shared == bytes.fromhex(vec["shared_secret"])

    sender = setup.key_schedule("S", mode, shared, info, psk, psk_id)
    recipient = setup.key_schedule("R", mode, shared, info, psk, psk_id)
    assert sender.key == recipient.key == bytes.fromhex(vec["key"])
    assert sender.base_nonce == recipient.base_nonce == bytes.fromhex(vec["base_nonce"])
    assert (
        sender.exporter_secret == recipient.exporter_secret == bytes.fromhex(vec["exporter_secret"])
    )

    for message in vec["encryptions"]:
        aad = bytes.fromhex(message["aad"])
        pt = bytes.fromhex(message["pt"])
        ct = bytes.fromhex(message["ct"])
        assert sender.seal(aad, pt) == ct
        assert recipient.open(aad, ct) == pt

    assert sender.export(b"exp", 32) == bytes.fromhex(vec["export"])
    assert recipient.export(b"exp", 32) == bytes.fromhex(vec["export"])
