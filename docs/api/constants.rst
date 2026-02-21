Constants
=========

Algorithm identifiers and HPKE modes (RFC 9180 §5, §7).

.. automodule:: rfc9180.constants
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Parameter Dictionaries
-----------------------

The module also defines parameter dictionaries for algorithm sizes:

- **KEM_PARAMS**: Per-KEM sizes (``Nsecret``, ``Nenc``, ``Npk``, ``Nsk``, ``Ndh``)
- **KDF_PARAMS**: Per-KDF sizes (``Nh``)
- **AEAD_PARAMS**: Per-AEAD sizes (``Nk``, ``Nn``, ``Nt``)

These are used internally and can be useful when implementing custom wire formats
(e.g. ``Nenc`` for ``parse_header``).
