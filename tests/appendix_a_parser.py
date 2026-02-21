import re
from pathlib import Path
from typing import Any

_SETUP_HEADER_RE = re.compile(r"^(A\.\d+\.\d+)\.\s+.+Setup Information$")
_ENCRYPTION_HEADER_RE = re.compile(r"^(A\.\d+\.\d+)\.1\.\s+Encryptions$")
_EXPORT_HEADER_RE = re.compile(r"^(A\.\d+\.\d+)\.2\.\s+Exported Values$")
_KEY_VALUE_RE = re.compile(r"^\s{3}([A-Za-z_ ]+):\s*(.*)$")
_SETUP_FIELD_CANONICAL = {
    "ikme": "ikmE",
    "ikmr": "ikmR",
    "ikms": "ikmS",
    "pkem": "pkEm",
    "pkrm": "pkRm",
    "pksm": "pkSm",
    "skem": "skEm",
    "skrm": "skRm",
    "sksm": "skSm",
}


def _is_hex_line(line: str) -> bool:
    s = line.strip().replace(" ", "")
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)


def _normalize_hex(value: str) -> str:
    return value.strip().replace(" ", "")


def _finalize_case(case: dict[str, Any]) -> dict[str, Any]:
    for k in ("mode", "kem_id", "kdf_id", "aead_id"):
        case[k] = int(case[k])

    for export_case in case["exports"]:
        export_case["L"] = int(export_case["L"])

    # Keep schema aligned with JSON vectors used by existing tests.
    case.setdefault("psk", "")
    case.setdefault("psk_id", "")
    case.setdefault("ikmS", "")
    case.setdefault("pkSm", "")
    case.setdefault("skSm", "")
    case.setdefault("encryptions", [])
    case.setdefault("exports", [])
    return case


def parse_appendix_a_vectors(rfc_path: str | Path) -> list[dict[str, Any]]:
    path = Path(rfc_path)
    lines = path.read_text(encoding="utf-8").splitlines()

    # Parse only Appendix A onwards.
    appendix_indices = [
        i for i, line in enumerate(lines) if line.strip() == "Appendix A.  Test Vectors"
    ]
    if not appendix_indices:
        raise ValueError("Could not locate 'Appendix A.  Test Vectors' in RFC text")
    # RFC text includes this heading in the table of contents too; parse from the actual appendix.
    start = appendix_indices[-1]

    vectors: list[dict[str, Any]] = []
    current_case: dict[str, Any] | None = None
    current_block: str | None = None  # "setup", "encryptions", "exports"
    current_encryption: dict[str, Any] | None = None
    current_export: dict[str, Any] | None = None
    pending_hex_target: tuple[dict[str, Any], str] | None = None

    def flush_encryption() -> None:
        nonlocal current_encryption
        if current_case is not None and current_encryption is not None:
            current_case["encryptions"].append(current_encryption)
            current_encryption = None

    def flush_export() -> None:
        nonlocal current_export
        if current_case is not None and current_export is not None:
            current_case["exports"].append(current_export)
            current_export = None

    def flush_case() -> None:
        nonlocal current_case
        if current_case is None:
            return
        flush_encryption()
        flush_export()
        vectors.append(_finalize_case(current_case))
        current_case = None

    for raw in lines[start + 1 :]:
        line = raw.rstrip()
        stripped = line.strip()

        # Continuation of wrapped hex values.
        if pending_hex_target is not None and _is_hex_line(stripped):
            target, key = pending_hex_target
            target[key] += _normalize_hex(stripped)
            continue
        pending_hex_target = None

        if not stripped:
            continue

        setup_match = _SETUP_HEADER_RE.match(stripped)
        if setup_match:
            flush_case()
            section_id = setup_match.group(1)
            current_case = {
                "section": section_id,
                "encryptions": [],
                "exports": [],
            }
            current_block = "setup"
            continue

        if current_case is None:
            # Skip preface text and ciphersuite headlines (A.n.).
            continue

        if _ENCRYPTION_HEADER_RE.match(stripped):
            flush_encryption()
            current_block = "encryptions"
            continue

        if _EXPORT_HEADER_RE.match(stripped):
            flush_encryption()
            flush_export()
            current_block = "exports"
            continue

        key_value_match = _KEY_VALUE_RE.match(line)
        if not key_value_match:
            continue

        key_name = key_value_match.group(1).strip().lower().replace(" ", "_")
        value = key_value_match.group(2).strip()

        if current_block == "setup":
            target = current_case
            canonical_key = _SETUP_FIELD_CANONICAL.get(key_name, key_name)
            if key_name in {"mode", "kem_id", "kdf_id", "aead_id"}:
                target[key_name] = value
            else:
                normalized = _normalize_hex(value)
                target[canonical_key] = normalized
                pending_hex_target = (target, canonical_key)

        elif current_block == "encryptions":
            if key_name == "sequence_number":
                flush_encryption()
                current_encryption = {"sequence_number": int(value)}
            if current_encryption is None:
                current_encryption = {}
            if key_name != "sequence_number":
                normalized = _normalize_hex(value)
                current_encryption[key_name] = normalized
                pending_hex_target = (current_encryption, key_name)

        elif current_block == "exports":
            if key_name == "exporter_context":
                flush_export()
                current_export = {"exporter_context": _normalize_hex(value)}
                pending_hex_target = (current_export, "exporter_context")
            else:
                if current_export is None:
                    current_export = {"exporter_context": ""}
                if key_name == "l":
                    current_export["L"] = value
                else:
                    normalized = _normalize_hex(value)
                    current_export[key_name] = normalized
                    pending_hex_target = (current_export, key_name)

    flush_case()

    if not vectors:
        raise ValueError("No Appendix A vectors were parsed")
    return vectors
