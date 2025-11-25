from enum import IntEnum


# HPKE Modes (RFC 9180 §5, Table 1)
class HPKEMode(IntEnum):
    """
    HPKE mode identifiers as defined in RFC 9180 §5, Table 1.

    Attributes
    ----------
    MODE_BASE : int
        Base mode (0x00).
    MODE_PSK : int
        Pre-shared key mode (0x01).
    MODE_AUTH : int
        Authenticated mode (0x02).
    MODE_AUTH_PSK : int
        Authenticated pre-shared key mode (0x03).
    """
    MODE_BASE = 0x00
    MODE_PSK = 0x01
    MODE_AUTH = 0x02
    MODE_AUTH_PSK = 0x03

# KEM Algorithm IDs (RFC 9180 §7.1, Table 2)
class KEMID(IntEnum):
    """
    Key Encapsulation Mechanism algorithm identifiers (RFC 9180 §7.1, Table 2).

    Attributes
    ----------
    DHKEM_P256_HKDF_SHA256 : int
        P-256 curve with HKDF-SHA256 (0x0010).
    DHKEM_P384_HKDF_SHA384 : int
        P-384 curve with HKDF-SHA384 (0x0011).
    DHKEM_P521_HKDF_SHA512 : int
        P-521 curve with HKDF-SHA512 (0x0012).
    DHKEM_X25519_HKDF_SHA256 : int
        X25519 with HKDF-SHA256 (0x0020).
    DHKEM_X448_HKDF_SHA512 : int
        X448 with HKDF-SHA512 (0x0021).
    """
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021

# KDF Algorithm IDs (RFC 9180 §7.2, Table 3)
class KDFID(IntEnum):
    """
    Key Derivation Function algorithm identifiers (RFC 9180 §7.2, Table 3).

    Attributes
    ----------
    HKDF_SHA256 : int
        HKDF with SHA-256 (0x0001).
    HKDF_SHA384 : int
        HKDF with SHA-384 (0x0002).
    HKDF_SHA512 : int
        HKDF with SHA-512 (0x0003).
    """
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003

# AEAD Algorithm IDs (RFC 9180 §7.3, Table 5)
class AEADID(IntEnum):
    """
    Authenticated Encryption with Associated Data algorithm identifiers
    (RFC 9180 §7.3, Table 5).

    Attributes
    ----------
    AES_128_GCM : int
        AES-128 in GCM mode (0x0001).
    AES_256_GCM : int
        AES-256 in GCM mode (0x0002).
    CHACHA20_POLY1305 : int
        ChaCha20-Poly1305 (0x0003).
    EXPORT_ONLY : int
        Export-only mode, no encryption (0xFFFF).
    """
    AES_128_GCM = 0x0001
    AES_256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003
    EXPORT_ONLY = 0xFFFF

# Algorithm parameter sizes
# KEM params: Nsecret, Nenc, Npk, Nsk, Ndh
KEM_PARAMS = {
    KEMID.DHKEM_P256_HKDF_SHA256: {
        'Nsecret': 32, 'Nenc': 65, 'Npk': 65, 'Nsk': 32, 'Ndh': 32
    },
    KEMID.DHKEM_P384_HKDF_SHA384: {
        'Nsecret': 48, 'Nenc': 97, 'Npk': 97, 'Nsk': 48, 'Ndh': 48
    },
    KEMID.DHKEM_P521_HKDF_SHA512: {
        'Nsecret': 64, 'Nenc': 133, 'Npk': 133, 'Nsk': 66, 'Ndh': 66
    },
    KEMID.DHKEM_X25519_HKDF_SHA256: {
        'Nsecret': 32, 'Nenc': 32, 'Npk': 32, 'Nsk': 32, 'Ndh': 32
    },
    KEMID.DHKEM_X448_HKDF_SHA512: {
        'Nsecret': 64, 'Nenc': 56, 'Npk': 56, 'Nsk': 56, 'Ndh': 56
    }
}

# KDF params: Nh
KDF_PARAMS = {
    KDFID.HKDF_SHA256: {'Nh': 32},
    KDFID.HKDF_SHA384: {'Nh': 48},
    KDFID.HKDF_SHA512: {'Nh': 64}
}

# AEAD params: Nk (key), Nn (nonce), Nt (tag)
AEAD_PARAMS = {
    AEADID.AES_128_GCM: {'Nk': 16, 'Nn': 12, 'Nt': 16},
    AEADID.AES_256_GCM: {'Nk': 32, 'Nn': 12, 'Nt': 16},
    AEADID.CHACHA20_POLY1305: {'Nk': 32, 'Nn': 12, 'Nt': 16},
    AEADID.EXPORT_ONLY: {'Nk': 0, 'Nn': 0, 'Nt': 0}
}


