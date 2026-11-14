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
around 50–100) so they run comfortably in CI. For heavier local fuzzing, you can override
Hypothesis settings via environment variables, for example:

```bash
HYPOTHESIS_MAX_EXAMPLES=500 pytest tests/fuzz -q
```

