# rfc9180-py

A Python implementation of **Hybrid Public Key Encryption (HPKE)** as specified in [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.txt).

# Overview

HPKE provides a variant of public key encryption for arbitrary-sized plaintexts. It combines an asymmetric Key Encapsulation Mechanism (KEM), a Key Derivation Function (KDF), and an Authenticated Encryption with Associated Data (AEAD) algorithm to provide secure encryption with optional authentication.

This library implements the core HPKE specification using Python's `cryptography` library, providing both single-shot and multi-shot APIs for all HPKE modes.

## Features

- **All HPKE Modes**: Base, PSK, Auth, and AuthPSK modes
- **Multiple Ciphersuites**: Support for various KEM, KDF, and AEAD combinations
- **Single-Shot APIs**: Convenient one-call encryption/decryption
- **Context APIs**: Multi-message encryption contexts with automatic nonce management
- **Secret Export**: Export application secrets from HPKE contexts
- **RFC 9180 Compliant**: Follows the specification closely with proper domain separation and validation

## Installation

```bash
pip install cryptography
```

The library uses Python's standard `cryptography` library for all cryptographic primitives.

## Quick Start

```python
from hpke import HPKE, KEMID, KDFID, AEADID

# Create HPKE instance with default ciphersuite (X25519 + HKDF-SHA256 + AES-128-GCM)
hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)

# Generate recipient key pair
skR, pkR = hpke.kem.generate_key_pair()

# Single-shot encryption (Base mode)
info = b"application-info"
aad = b"additional-data"
plaintext = b"secret message"
enc, ciphertext = hpke.seal_base(pkR, info, aad, plaintext)

# Single-shot decryption
decrypted = hpke.open_base(enc, skR, info, aad, ciphertext)
assert decrypted == plaintext

# Multi-shot encryption
enc, ctx_sender = hpke.setup.setup_base_sender(pkR, info)
ct1 = ctx_sender.seal(aad, b"message 1")
ct2 = ctx_sender.seal(aad, b"message 2")

# Multi-shot decryption
ctx_recipient = hpke.setup.setup_base_recipient(enc, skR, info)
pt1 = ctx_recipient.open(aad, ct1)
pt2 = ctx_recipient.open(aad, ct2)
```

## Implementation Status

### ✅ Implemented (RFC 9180 Compliance)

#### Section 4: Cryptographic Dependencies
- ✅ **DHKEM (DH-Based KEM)**: Full implementation with ExtractAndExpand
- ✅ **LabeledExtract**: RFC 9180 §4 with proper "HPKE-v1" domain separation
- ✅ **LabeledExpand**: RFC 9180 §4 with length prefixing

#### Section 5: Hybrid Public Key Encryption
- ✅ **SetupBaseS/R**: Base mode setup (Section 5.1.1)
- ✅ **SetupPSKS/R**: PSK mode setup (Section 5.1.2)
- ✅ **SetupAuthS/R**: Auth mode setup (Section 5.1.3)
- ✅ **SetupAuthPSKS/R**: AuthPSK mode setup (Section 5.1.4)
- ✅ **Key Schedule**: Full implementation with proper PSK validation
- ✅ **Context Seal/Open**: Multi-message encryption with sequence number management
- ✅ **Secret Export**: Context export functionality (Section 5.3)

#### Section 6: Single-Shot APIs
- ✅ **Seal/Open APIs**: All four modes (Base, PSK, Auth, AuthPSK)
- ✅ **Export APIs**: Single-shot secret export for all modes

#### Section 7: Algorithm Identifiers

**KEMs (Section 7.1)**:
- ✅ **DHKEM_X25519_HKDF_SHA256** (0x0020): Full implementation
  - ✅ Key generation
  - ✅ Key derivation with RFC 7748 clamping
  - ✅ Serialization/deserialization
  - ✅ All-zero DH output validation
- ✅ **DHKEM_P256_HKDF_SHA256** (0x0010): Full implementation
  - ✅ Key generation
  - ✅ Key derivation with rejection sampling
  - ✅ Serialization/deserialization
  - ✅ Partial public key validation
- ✅ **DHKEM_P384_HKDF_SHA384** (0x0011): Full implementation
  - ✅ Key generation
  - ✅ Key derivation with rejection sampling
  - ✅ Serialization/deserialization
- ✅ **DHKEM_P521_HKDF_SHA512** (0x0012): Full implementation
  - ✅ Key generation
  - ✅ Key derivation with rejection sampling
  - ✅ Serialization/deserialization
- ✅ **DHKEM_X448_HKDF_SHA512** (0x0021): Full implementation
  - ✅ Key generation
  - ✅ Key derivation with RFC 7748 clamping
  - ✅ Serialization/deserialization

**KDFs (Section 7.2)**:
- ✅ **HKDF_SHA256** (0x0001): Full implementation
- ✅ **HKDF_SHA384** (0x0002): Full implementation
- ✅ **HKDF_SHA512** (0x0003): Full implementation

**AEADs (Section 7.3)**:
- ✅ **AES_128_GCM** (0x0001): Full implementation
- ✅ **AES_256_GCM** (0x0002): Full implementation
- ✅ **CHACHA20_POLY1305** (0x0003): Full implementation
- ✅ **EXPORT_ONLY** (0xFFFF): Full implementation (export-only mode)

#### Section 7.1: KEM Operations
- ✅ **SerializePublicKey/DeserializePublicKey**: Implemented for all supported KEMs
- ✅ **SerializePrivateKey/DeserializePrivateKey**: Implemented for all supported KEMs
- ✅ **DeriveKeyPair**: Implemented with proper rejection sampling/clamping
- ✅ **Validation**: Input/output validation per Section 7.1.4

#### Section 8: API Considerations
- ✅ **AAD Support**: Full support for additional authenticated data
- ✅ **Error Handling**: Comprehensive exception hierarchy

#### Section 9: Security Considerations
- ✅ **Domain Separation**: Proper suite ID construction and labeled operations
- ✅ **PSK Recommendations**: Enforced minimum entropy requirements
- ✅ **Nonce Management**: Automatic sequence number handling with overflow protection
- ✅ **Key Reuse**: Proper ephemeral key generation per message

### ❌ Not Implemented

#### Section 10: Message Encoding
- ✅ **Helpers Provided**: This library provides application-level helpers to encode/decode messages with a self-describing header per RFC §10 guidance. See below.

#### Section 9.7: Application-Level Features (Non-Goals)
The following are explicitly **not** provided by HPKE and must be handled by applications:
- ❌ **Message Ordering**: No built-in message ordering (Section 9.7.1)
- ❌ **Downgrade Prevention**: No protocol version negotiation (Section 9.7.2)
- ❌ **Replay Protection**: No built-in replay detection (Section 9.7.3)
- ❌ **Forward Secrecy**: Requires application-level key rotation (Section 9.7.4)
- ❌ **Plaintext Length Hiding**: No padding mechanisms (Section 9.7.6)

Note: These are intentional non-goals per RFC 9180 and should be handled at the application layer.

## Supported Ciphersuites

| KEM | KDF | AEAD | Status |
|-----|-----|------|--------|
| X25519 | HKDF-SHA256 | AES-128-GCM | ✅ |
| X25519 | HKDF-SHA256 | AES-256-GCM | ✅ |
| X25519 | HKDF-SHA256 | ChaCha20-Poly1305 | ✅ |
| X25519 | HKDF-SHA256 | EXPORT_ONLY | ✅ |
| P-256 | HKDF-SHA256 | AES-128-GCM | ✅ |
| P-256 | HKDF-SHA256 | AES-256-GCM | ✅ |
| P-256 | HKDF-SHA256 | ChaCha20-Poly1305 | ✅ |
| P-256 | HKDF-SHA256 | EXPORT_ONLY | ✅ |
| P-384 | HKDF-SHA384 | AES-128-GCM | ✅ |
| P-384 | HKDF-SHA384 | AES-256-GCM | ✅ |
| P-384 | HKDF-SHA384 | ChaCha20-Poly1305 | ✅ |
| P-384 | HKDF-SHA384 | EXPORT_ONLY | ✅ |
| P-521 | HKDF-SHA512 | AES-128-GCM | ✅ |
| P-521 | HKDF-SHA512 | AES-256-GCM | ✅ |
| P-521 | HKDF-SHA512 | ChaCha20-Poly1305 | ✅ |
| P-521 | HKDF-SHA512 | EXPORT_ONLY | ✅ |
| X448 | HKDF-SHA512 | AES-128-GCM | ✅ |
| X448 | HKDF-SHA512 | AES-256-GCM | ✅ |
| X448 | HKDF-SHA512 | ChaCha20-Poly1305 | ✅ |
| X448 | HKDF-SHA512 | EXPORT_ONLY | ✅ |

## API Documentation

### High-Level API

```python
from hpke import HPKE, KEMID, KDFID, AEADID

# Create HPKE instance
hpke = HPKE(kem_id, kdf_id, aead_id)

# Access primitives
hpke.kem    # KEM instance
hpke.kdf    # KDF instance
hpke.aead   # AEAD instance
hpke.setup  # Setup functions
```

### Single-Shot APIs

```python
# Base mode
enc, ct = hpke.seal_base(pkR, info, aad, pt)
pt = hpke.open_base(enc, skR, info, aad, ct)

# PSK mode
enc, ct = hpke.seal_psk(pkR, info, aad, pt, psk, psk_id)
pt = hpke.open_psk(enc, skR, info, aad, ct, psk, psk_id)

# Auth mode
enc, ct = hpke.seal_auth(pkR, info, aad, pt, skS)
pt = hpke.open_auth(enc, skR, info, aad, ct, pkS)

# AuthPSK mode
enc, ct = hpke.seal_auth_psk(pkR, info, aad, pt, psk, psk_id, skS)
pt = hpke.open_auth_psk(enc, skR, info, aad, ct, psk, psk_id, pkS)
```

### Context APIs

```python
# Setup contexts
enc, ctx_s = hpke.setup.setup_base_sender(pkR, info)
ctx_r = hpke.setup.setup_base_recipient(enc, skR, info)

# Encrypt/decrypt multiple messages
ct1 = ctx_s.seal(aad, pt1)
ct2 = ctx_s.seal(aad, pt2)
pt1 = ctx_r.open(aad, ct1)
pt2 = ctx_r.open(aad, ct2)

# Export secrets
secret = ctx_s.export(exporter_context, length)
```

## Testing

The library includes comprehensive unit tests and support for RFC 9180 test vectors:

```bash
# Run all tests
pytest tests/

# Run specific test suites
pytest tests/test_kem.py
pytest tests/test_vectors.py
```

## Section 10: Message Encoding Helpers

Applications often need a wire format. This library provides simple helpers for a self-describing header:

```python
from hpke import append_header, parse_header
from hpke.constants import HPKEMode

enc, ct = hpke.seal_base(pkR, info, aad, pt)
msg = append_header(enc, ct, int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id), int(HPKEMode.MODE_BASE))
kem_id2, kdf_id2, aead_id2, mode2, enc2, ct2 = parse_header(msg, enc_len=hpke.kem.Nenc)
pt2 = hpke.open_base(enc2, skR, info, aad, ct2)
```

Note: This is an application-level format following RFC 9180 §10 guidance; applications may define alternative encodings.

## KEM/KDF Decoupling

Per RFC 9180 §7.1, each KEM mandates a specific hash/KDF. This implementation decouples the KEM’s internal KDF from the ciphersuite KDF used in the key schedule (§5.1): KEMs self-select their mandated hash; the suite KDF (e.g., HKDF-SHA256) is used for key schedule and exports.

## Security Considerations

- **PSK Entropy**: PSKs must have at least 32 bytes of entropy (enforced)
- **Key Reuse**: Ephemeral keys are generated fresh for each encryption
- **Nonce Management**: Sequence numbers are automatically managed with overflow protection
- **Validation**: All inputs are validated per RFC 9180 requirements

## References

- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.txt)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869.txt)
- [RFC 7748: Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748.txt)

## License

This implementation follows the same licensing terms as RFC 9180 (IETF Trust).

## Contributing

Contributions are welcome! Areas for improvement:
- Performance optimizations
- Additional test vectors
- Documentation improvements
