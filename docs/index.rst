.. rfc9180 documentation master file

rfc9180-py
===========

A Python implementation of **Hybrid Public Key Encryption (HPKE)** as specified in
`RFC 9180 <https://www.rfc-editor.org/rfc/rfc9180.txt>`_.

Overview
--------

HPKE provides a variant of public key encryption for arbitrary-sized plaintexts. It combines:

- A **Key Encapsulation Mechanism (KEM)** — asymmetric
- A **Key Derivation Function (KDF)** — for key schedule and exports
- An **Authenticated Encryption with Associated Data (AEAD)** algorithm

This library implements the core HPKE specification using Python's ``cryptography`` library,
with both single-shot and multi-shot (context) APIs for all HPKE modes.

Features
--------

- **All HPKE modes**: Base, PSK, Auth, and AuthPSK
- **Multiple ciphersuites**: KEM (X25519, X448, P-256, P-384, P-521), KDF (HKDF-SHA256/384/512), AEAD (AES-128/256-GCM, ChaCha20-Poly1305, EXPORT_ONLY)
- **Single-shot APIs**: One-call seal/open per mode
- **Context APIs**: Multi-message encryption with automatic nonce management
- **Secret export**: Export application secrets from HPKE contexts
- **Key management**: Generate, derive, serialize keys; accept keys as bytes or key objects
- **Message encoding helpers**: Self-describing header format (``append_header`` / ``parse_header``)

Contents
--------

.. toctree::
   :maxdepth: 2

   installation
   quickstart
   api/index

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
