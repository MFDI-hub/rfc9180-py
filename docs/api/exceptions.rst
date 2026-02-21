Exceptions
==========

HPKE-specific exception hierarchy. All exceptions inherit from :class:`HPKEError`.

.. automodule:: rfc9180.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Exception Summary
-----------------

- **ValidationError**: KEM input/output validation (e.g. all-zero DH outputs)
- **DeserializeError**: Invalid key format or length during deserialization
- **EncapError**: Key encapsulation failure
- **DecapError**: Key decapsulation failure (invalid enc, wrong key)
- **OpenError**: AEAD decryption failure (tampered data, wrong key)
- **MessageLimitReachedError**: Sequence number overflow (max messages exceeded)
- **DeriveKeyPairError**: Key pair derivation failed (e.g. rejection sampling)
