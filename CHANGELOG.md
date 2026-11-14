# Changelog

## 0.4.0

Security fixes for the 0.3.0 release published to PyPI on 2026-02-22. Upgrade from 0.3.0.

- X25519 and X448 private-key serialization uses `private_bytes_raw()`. 0.3.0 cached derived secret bytes in a dict keyed by `id()`, so a recycled id could return another key's secret and deleted keys could leave secret bytes retained.
- `Context.seal` and `Context.open` hold a lock across nonce allocation, the AEAD call, and the sequence increment. 0.3.0 could encrypt two concurrent messages under one nonce.
- The message limit is checked before the AEAD runs. 0.3.0 encrypted at the last sequence number and then raised, so a retry repeated that nonce.
- `DeserializeError` and `ValidationError` propagate from KEM operations. `AEAD.seal` no longer turns programming errors into `MessageLimitReachedError`.
- PSK handling follows RFC 9180 `VerifyPSKInputs` only. Entropy remains the caller's responsibility (RFC 9180 §9.5). `key_schedule` accepts only roles `"S"` and `"R"`.
- `parse_header` checks `kem_id`, `kdf_id`, `aead_id`, and `mode`, and requires the ciphertext to be at least one AEAD tag.
- `serialize_public_key(bytes)` and `serialize_private_key(bytes)` deserialize before returning.
- `base64url_decode` accepts only canonical unpadded base64url.
- AES-GCM contexts stop at 2^32 messages per key. ChaCha20-Poly1305 stops one nonce short of the RFC pseudocode (`2^96 - 1` messages).
- Python 3.10+ imports `TypeAlias` from `typing`.

## 0.3.0

Previous PyPI release. Affected by the serialization, nonce, and error-handling bugs fixed in 0.4.0.
