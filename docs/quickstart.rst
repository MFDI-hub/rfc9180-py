Quick Start
===========

Create an HPKE instance
-----------------------

Use the main ``HPKE`` class with algorithm identifiers, or the convenience function
``create_hpke()`` for the default ciphersuite (X25519 + HKDF-SHA256 + AES-128-GCM):

.. code-block:: python

   from rfc9180 import HPKE, KEMID, KDFID, AEADID, create_hpke

   # Explicit ciphersuite
   hpke = HPKE(KEMID.DHKEM_X25519_HKDF_SHA256, KDFID.HKDF_SHA256, AEADID.AES_128_GCM)

   # Or defaults
   hpke = create_hpke()

Key generation and serialization
--------------------------------

.. code-block:: python

   # Generate recipient key pair
   skR, pkR = hpke.generate_key_pair()

   # Serialize for storage or transmission
   pk_bytes = hpke.serialize_public_key(pkR)
   sk_bytes = hpke.serialize_private_key(skR)

   # seal/open accept both bytes and key objects
   enc, ct = hpke.seal_base(pk_bytes, info, aad, pt)

Single-shot encryption (Base mode)
----------------------------------

.. code-block:: python

   info = b"application-info"
   aad = b"additional-data"
   plaintext = b"secret message"

   enc, ciphertext = hpke.seal_base(pkR, info, aad, plaintext)
   decrypted = hpke.open_base(enc, skR, info, aad, ciphertext)
   assert decrypted == plaintext

Other single-shot modes
------------------------

**PSK mode** (pre-shared key; must have at least 32 bytes of entropy):

.. code-block:: python

   psk = b"pre-shared-key-with-sufficient-entropy"
   psk_id = b"psk-identifier"
   enc, ct = hpke.seal_psk(pkR, info, aad, pt, psk, psk_id)
   pt = hpke.open_psk(enc, skR, info, aad, ct, psk, psk_id)

**Auth mode** (sender authentication):

.. code-block:: python

   skS, pkS = hpke.generate_key_pair()
   enc, ct = hpke.seal_auth(pkR, info, aad, pt, skS)
   pt = hpke.open_auth(enc, skR, info, aad, ct, pkS)

**AuthPSK mode** (authenticated + pre-shared key):

.. code-block:: python

   enc, ct = hpke.seal_auth_psk(pkR, info, aad, pt, psk, psk_id, skS)
   pt = hpke.open_auth_psk(enc, skR, info, aad, ct, psk, psk_id, pkS)

Multi-shot (context) API
------------------------

Use the setup methods to get sender/recipient contexts, then seal/open multiple messages:

.. code-block:: python

   enc, ctx_sender = hpke.setup.setup_base_sender(pkR, info)
   ctx_recipient = hpke.setup.setup_base_recipient(enc, skR, info)

   ct1 = ctx_sender.seal(aad, b"message 1")
   ct2 = ctx_sender.seal(aad, b"message 2")

   pt1 = ctx_recipient.open(aad, ct1)
   pt2 = ctx_recipient.open(aad, ct2)

Secret export
-------------

.. code-block:: python

   secret = ctx_sender.export(b"exporter-context", 32)

Message encoding helpers
------------------------

Encode/parse a self-describing wire format (header + enc + ct):

.. code-block:: python

   from rfc9180 import append_header, parse_header
   from rfc9180.constants import HPKEMode

   enc, ct = hpke.seal_base(pkR, info, aad, pt)
   msg = append_header(
       enc, ct,
       int(hpke.kem_id), int(hpke.kdf_id), int(hpke.aead_id),
       int(HPKEMode.MODE_BASE),
   )

   kem_id, kdf_id, aead_id, mode, enc2, ct2 = parse_header(msg, enc_len=hpke.kem.Nenc)
   pt2 = hpke.open_base(enc2, skR, info, aad, ct2)

Error handling
--------------

.. code-block:: python

   from rfc9180.exceptions import OpenError, MessageLimitReachedError

   try:
       pt = hpke.open_base(enc, skR, info, aad, ct)
   except OpenError:
       # Decryption failed (wrong key, tampered data, etc.)
       pass

For full API details, see :doc:`api/index`.
