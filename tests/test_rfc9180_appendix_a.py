from pathlib import Path

import pytest

from rfc9180.constants import HPKEMode
from rfc9180.setup import HPKESetup
from rfc9180.utils import I2OSP, concat
from tests.appendix_a_parser import parse_appendix_a_vectors
from tests.vector_helpers import get_aead, get_kdf, get_kem_class, get_mode


def _load_appendix_a_vectors():
    rfc_path = Path(__file__).resolve().parents[1] / "rfc9180.txt"
    return parse_appendix_a_vectors(rfc_path)


APPENDIX_A_VECTORS = _load_appendix_a_vectors()


@pytest.mark.parametrize("vec", APPENDIX_A_VECTORS, ids=[v["section"] for v in APPENDIX_A_VECTORS])
def test_appendix_a_vector(vec):
    kem_id = vec["kem_id"]
    kdf_id = vec["kdf_id"]
    aead_id = vec["aead_id"]
    mode = get_mode(vec["mode"])

    kem = get_kem_class(kem_id)
    kdf = get_kdf(kdf_id)
    aead = get_aead(aead_id)
    setup = HPKESetup(kem, kdf, aead)

    ikmR = bytes.fromhex(vec["ikmR"])
    skR, pkR = kem.derive_key_pair(ikmR)
    assert kem.serialize_public_key(pkR) == bytes.fromhex(vec["pkRm"])
    assert kem.serialize_private_key(skR) == bytes.fromhex(vec["skRm"])

    ikmE = bytes.fromhex(vec["ikmE"])
    skE, pkE = kem.derive_key_pair(ikmE)
    assert kem.serialize_public_key(pkE) == bytes.fromhex(vec["pkEm"])
    assert kem.serialize_private_key(skE) == bytes.fromhex(vec["skEm"])

    enc = bytes.fromhex(vec["enc"])
    assert kem.serialize_public_key(pkE) == enc

    skS = None
    pkS = None
    if mode in (HPKEMode.MODE_AUTH, HPKEMode.MODE_AUTH_PSK):
        ikmS = bytes.fromhex(vec["ikmS"])
        skS, pkS = kem.derive_key_pair(ikmS)
        assert kem.serialize_public_key(pkS) == bytes.fromhex(vec["pkSm"])
        assert kem.serialize_private_key(skS) == bytes.fromhex(vec["skSm"])

    psk = bytes.fromhex(vec["psk"]) if vec.get("psk") else b""
    psk_id = bytes.fromhex(vec["psk_id"]) if vec.get("psk_id") else b""
    info = bytes.fromhex(vec["info"])

    if mode in (HPKEMode.MODE_BASE, HPKEMode.MODE_PSK):
        shared_secret = kem.decap(enc, skR)
    else:
        shared_secret = kem.auth_decap(enc, skR, pkS)

    assert shared_secret == bytes.fromhex(vec["shared_secret"])

    # Verify intermediate key schedule inputs/values from Appendix A.
    psk_id_hash = kdf.labeled_extract(
        salt=b"",
        label="psk_id_hash",
        ikm=psk_id,
        suite_id=setup.suite_id,
    )
    info_hash = kdf.labeled_extract(
        salt=b"",
        label="info_hash",
        ikm=info,
        suite_id=setup.suite_id,
    )
    key_schedule_context = concat(I2OSP(mode, 1), psk_id_hash, info_hash)
    assert key_schedule_context == bytes.fromhex(vec["key_schedule_context"])

    secret = kdf.labeled_extract(
        salt=shared_secret,
        label="secret",
        ikm=psk,
        suite_id=setup.suite_id,
    )
    assert secret == bytes.fromhex(vec["secret"])

    ctx_sender = setup.key_schedule("S", mode, shared_secret, info, psk=psk, psk_id=psk_id)
    ctx_recipient = setup.key_schedule("R", mode, shared_secret, info, psk=psk, psk_id=psk_id)

    if vec.get("key"):
        key_expected = bytes.fromhex(vec["key"])
        assert ctx_sender.key == key_expected
        assert ctx_recipient.key == key_expected

    if vec.get("base_nonce"):
        base_nonce_expected = bytes.fromhex(vec["base_nonce"])
        assert ctx_sender.base_nonce == base_nonce_expected
        assert ctx_recipient.base_nonce == base_nonce_expected

    if vec.get("exporter_secret"):
        exporter_secret_expected = bytes.fromhex(vec["exporter_secret"])
        assert ctx_sender.exporter_secret == exporter_secret_expected
        assert ctx_recipient.exporter_secret == exporter_secret_expected

    if vec["encryptions"]:
        for enc_data in vec["encryptions"]:
            ctx_sender_enc = setup.key_schedule("S", mode, shared_secret, info, psk=psk, psk_id=psk_id)
            ctx_sender_enc.seq = enc_data["sequence_number"]
            aad = bytes.fromhex(enc_data["aad"])
            pt = bytes.fromhex(enc_data["pt"])
            ct_expected = bytes.fromhex(enc_data["ct"])
            nonce_expected = bytes.fromhex(enc_data["nonce"])

            assert ctx_sender_enc.compute_nonce(ctx_sender_enc.seq) == nonce_expected
            assert ctx_sender_enc.seal(aad, pt) == ct_expected

        for enc_data in vec["encryptions"]:
            ctx_recipient_dec = setup.key_schedule("R", mode, shared_secret, info, psk=psk, psk_id=psk_id)
            ctx_recipient_dec.seq = enc_data["sequence_number"]
            aad = bytes.fromhex(enc_data["aad"])
            pt_expected = bytes.fromhex(enc_data["pt"])
            ct = bytes.fromhex(enc_data["ct"])
            nonce_expected = bytes.fromhex(enc_data["nonce"])

            assert ctx_recipient_dec.compute_nonce(ctx_recipient_dec.seq) == nonce_expected
            assert ctx_recipient_dec.open(aad, ct) == pt_expected

    for export_data in vec["exports"]:
        exporter_context = bytes.fromhex(export_data["exporter_context"])
        length = export_data["L"]
        expected = bytes.fromhex(export_data["exported_value"])
        assert ctx_sender.export(exporter_context, length) == expected
        assert ctx_recipient.export(exporter_context, length) == expected
