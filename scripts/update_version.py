"""Write one version string into pyproject.toml and src/rfc9180/__init__.py."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "rfc9180" / "__init__.py"
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def main(argv: list[str]) -> None:
    dry_run = "--dry-run" in argv
    args = [arg for arg in argv if arg != "--dry-run"]
    if len(args) != 1 or _VERSION.fullmatch(args[0]) is None:
        raise SystemExit("usage: update_version.py X.Y.Z [--dry-run]")
    version = args[0]

    project_text = PYPROJECT.read_text(encoding="utf-8")
    project_new, project_count = re.subn(
        r'(?m)^version = "[^"]+"',
        f'version = "{version}"',
        project_text,
        count=1,
    )
    init_text = INIT.read_text(encoding="utf-8")
    init_new, init_count = re.subn(
        r'(?m)^__version__: str = "[^"]+"',
        f'__version__: str = "{version}"',
        init_text,
        count=1,
    )
    if project_count != 1 or init_count != 1:
        raise SystemExit("version assignment not found in both files")
    if dry_run:
        print(f"would set version to {version}")
        return
    PYPROJECT.write_text(project_new, encoding="utf-8")
    INIT.write_text(init_new, encoding="utf-8")
    print(version)


if __name__ == "__main__":
    main(sys.argv[1:])
