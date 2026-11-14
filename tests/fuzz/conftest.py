"""Register the Hypothesis ``heavy`` profile.

Hypothesis does not read ``HYPOTHESIS_MAX_EXAMPLES``. Select this profile with
``HYPOTHESIS_PROFILE=heavy``. The per-test ``@settings(max_examples=...)``
decorators fix the count used in CI, so this hook raises that count to the
profile value only when ``heavy`` is active.
"""

from __future__ import annotations

import os
from pathlib import Path

from hypothesis import settings

settings.register_profile("heavy", max_examples=500)

_PROFILE = os.environ.get("HYPOTHESIS_PROFILE")
if _PROFILE:
    settings.load_profile(_PROFILE)

_FUZZ_DIR = Path(__file__).resolve().parent


def pytest_collection_modifyitems(items: list) -> None:
    if settings.get_current_profile_name() != "heavy":
        return
    examples = settings.get_profile("heavy").max_examples
    for item in items:
        path = getattr(item, "path", None)
        test = getattr(item, "obj", None)
        current = getattr(test, "_hypothesis_internal_use_settings", None)
        if path is None or current is None:
            continue
        if (
            _FUZZ_DIR not in Path(path).resolve().parents
            and Path(path).resolve().parent != _FUZZ_DIR
        ):
            continue
        test._hypothesis_internal_use_settings = settings(parent=current, max_examples=examples)
