# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.4.0 | Yes |
| 0.3.0 | No. Known vulnerabilities. |

0.4.0 is the only supported release. 0.3.0, including the build on PyPI, caches derived X25519 and X448 private keys by `id()` (a later key can serialize as an earlier key's secret), allows concurrent `seal` / `open` on one context to reuse a nonce, and encrypts once at the sequence limit before raising, so a retry repeats that nonce.

## Reporting a vulnerability

Report cryptographic issues privately through [GitHub Security Advisories](https://github.com/MFDI-hub/rfc9180-py/security/advisories/new).

Do not open a public GitHub issue for a vulnerability in this library.
