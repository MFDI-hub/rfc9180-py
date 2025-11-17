from enum import IntEnum

# HPKE Modes (RFC 9180 §5, Table 1)
class HPKEMode(IntEnum):
    MODE_BASE = 0x00
    MODE_PSK = 0x01
    MODE_AUTH = 0x02
    MODE_AUTH_PSK = 0x03

# KEM Algorithm IDs (RFC 9180 §7.1, Table 2)
class KEMID(IntEnum):
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021

# KDF Algorithm IDs (RFC 9180 §7.2, Table 3)
class KDFID(IntEnum):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003

# AEAD Algorithm IDs (RFC 9180 §7.3, Table 5)
class AEADID(IntEnum):
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


