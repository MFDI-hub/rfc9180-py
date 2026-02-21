Examples
========

This page provides complete, runnable examples for common HPKE use cases.

Complete Base Mode Example
--------------------------

.. code-block:: python

   from rfc9180 import HPKE, KEMID, KDFID, AEADID, create_hpke

   # Create HPKE with default ciphersuite (X25519 + HKDF-SHA256 + AES-128-GCM)
   hpke = create_hpke()

   # Generate recipient key pair
   skR, pkR = hpke.generate_key_pair()

   # Application context
   info = b"my-app-v1"
   aad = b"metadata"
   plaintext = b"Hello, HPKE!"

   # Encrypt
   enc, ciphertext = hpke.seal_base(pkR, info, aad, plaintext)

   # Decrypt
   decrypted = hpke.open_base(enc, skR, info, aad, ciphertext)
   assert decrypted == plaintext

   print("Encryption successful!")

Auth Mode with Sender Authentication
------------------------------------

.. code-block:: python

   from rfc9180 import HPKE, KEMID, KDFID, AEADID, create_hpke

   hpke = create_hpke()

   # Recipient keys
   skR, pkR = hpke.generate_key_pair()
   # Sender keys (for authentication)
   skS, pkS = hpke.generate_key_pair()

   info = b"authenticated-channel"
   aad = b""
   plaintext = b"Sensitive data"

   # Sender: encrypt with sender's private key (proves identity)
   enc, ct = hpke.seal_auth(pkR, info, aad, plaintext, skS)

   # Recipient: decrypt and verify sender's public key
   pt = hpke.open_auth(enc, skR, info, aad, ct, pkS)
   assert pt == plaintext

PSK Mode with Pre-Shared Key
----------------------------

.. code-block:: python

   from rfc9180 import HPKE, create_hpke

   hpke = create_hpke()

   # PSK must have at least 32 bytes of entropy
   psk = b"0" * 32  # In practice, use cryptographically random bytes
   psk_id = b"session-12345"

   skR, pkR = hpke.generate_key_pair()
   info = b"psk-channel"
   aad = b""
   plaintext = b"Shared secret protects this"

   enc, ct = hpke.seal_psk(pkR, info, aad, plaintext, psk, psk_id)
   pt = hpke.open_psk(enc, skR, info, aad, ct, psk, psk_id)
   assert pt == plaintext

Multi-Message Context (Streaming)
---------------------------------

.. code-block:: python

   from rfc9180 import create_hpke

   hpke = create_hpke()
   skR, pkR = hpke.generate_key_pair()

   info = b"streaming-session"
   aad = b""

   # Sender: setup once, encrypt many
   enc, ctx_sender = hpke.setup.setup_base_sender(pkR, info)
   ct1 = ctx_sender.seal(aad, b"message 1")
   ct2 = ctx_sender.seal(aad, b"message 2")
   ct3 = ctx_sender.seal(aad, b"message 3")

   # Recipient: setup once, decrypt many
   ctx_recipient = hpke.setup.setup_base_recipient(enc, skR, info)
   assert ctx_recipient.open(aad, ct1) == b"message 1"
   assert ctx_recipient.open(aad, ct2) == b"message 2"
   assert ctx_recipient.open(aad, ct3) == b"message 3"

Export-Only (Key Agreement)
---------------------------

.. code-block:: python

   from rfc9180 import create_hpke

   hpke = create_hpke()
   skR, pkR = hpke.generate_key_pair()

   info = b"key-agreement"
   exporter_context = b"shared-secret-context"
   length = 32

   # Sender derives shared secret
   enc, ctx_sender = hpke.setup.setup_base_sender(pkR, info)
   secret_sender = ctx_sender.export(exporter_context, length)

   # Recipient derives same secret
   ctx_recipient = hpke.setup.setup_base_recipient(enc, skR, info)
   secret_recipient = ctx_recipient.export(exporter_context, length)

   assert secret_sender == secret_recipient
   # Use secret_sender/secret_recipient for further crypto (e.g., HMAC, KDF)

Keys from JWK
-------------

.. code-block:: python

   import json
   from rfc9180 import HPKE, KEMKey, create_hpke

   hpke = create_hpke()

   # Generate keys and convert to JWK-like format for demo
   skR, pkR = hpke.generate_key_pair()
   pk_bytes = hpke.serialize_public_key(pkR)

   # Simulate loading from JWK (in practice, load from JSON/API)
   # For X25519, JWK has kty="OKP", crv="X25519", x=<base64url>
   from base64 import urlsafe_b64encode
   x_b64 = urlsafe_b64encode(pk_bytes).rstrip(b"=").decode("ascii")
   jwk = {"kty": "OKP", "crv": "X25519", "x": x_b64}

   # Load key from JWK
   pk_from_jwk = KEMKey.from_jwk(jwk)
   enc, ct = hpke.seal_base(pk_from_jwk, b"info", b"aad", b"secret")
   pt = hpke.open_base(enc, skR, b"info", b"aad", ct)
   assert pt == b"secret"

Self-Describing Wire Format
---------------------------

.. code-block:: python

   from rfc9180 import create_hpke, append_header, parse_header
   from rfc9180.constants import HPKEMode

   hpke = create_hpke()
   skR, pkR = hpke.generate_key_pair()

   info = b"app-info"
   aad = b""
   plaintext = b"Message with self-describing header"

   enc, ct = hpke.seal_base(pkR, info, aad, plaintext)

   # Encode: prepend HPKE header (kem_id, kdf_id, aead_id, mode)
   msg = append_header(
       enc, ct,
       int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id),
       int(HPKEMode.MODE_BASE),
   )

   # Parse: extract parameters and enc/ct from received message
   kem_id, kdf_id, aead_id, mode, enc2, ct2 = parse_header(msg, enc_len=hpke.kem.Nenc)
   pt = hpke.open_base(enc2, skR, info, aad, ct2)
   assert pt == plaintext

Different Ciphersuites
---------------------------

.. code-block:: python

   from rfc9180 import HPKE, KEMID, KDFID, AEADID

   # ChaCha20-Poly1305 (no AES, good for constrained environments)
   hpke_chacha = HPKE(
       KEMID.DHKEM_X25519_HKDF_SHA256,
       KDFID.HKDF_SHA256,
       AEADID.CHACHA20_POLY1305,
   )

   # P-256 (NIST curves)
   hpke_p256 = HPKE(
       KEMID.DHKEM_P256_HKDF_SHA256,
       KDFID.HKDF_SHA256,
       AEADID.AES_128_GCM,
   )

   # X448 + SHA-512 (higher security margin)
   hpke_x448 = HPKE(
       KEMID.DHKEM_X448_HKDF_SHA512,
       KDFID.HKDF_SHA512,
       AEADID.AES_256_GCM,
   )

   # Use any of them
   sk, pk = hpke_chacha.generate_key_pair()
   enc, ct = hpke_chacha.seal_base(pk, b"info", b"", b"test")
   pt = hpke_chacha.open_base(enc, sk, b"info", b"", ct)
