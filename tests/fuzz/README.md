## HPKE fuzz and property tests

This directory contains `hypothesis`-based fuzz/property tests for the HPKE implementation.

- **Running just fuzz tests**:

```bash
pytest tests/fuzz -q
```

- **Running the full test suite (including fuzz tests)**:

```bash
pytest
```

The fuzz tests use per-test `@settings` decorators with conservative defaults (e.g. `max_examples`
around 50–100) so they run comfortably in CI. `tests/fuzz/conftest.py` registers a Hypothesis
profile named `heavy` (`max_examples=500`) and applies it on top of those decorators.
Hypothesis selects a profile only from `HYPOTHESIS_PROFILE`:

```bash
HYPOTHESIS_PROFILE=heavy pytest tests/fuzz -q
```

