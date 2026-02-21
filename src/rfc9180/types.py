from __future__ import annotations

from typing import Union

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from typing_extensions import TypeAlias

KEMPublicKey: TypeAlias = Union[EllipticCurvePublicKey, X25519PublicKey, X448PublicKey]
KEMPrivateKey: TypeAlias = Union[EllipticCurvePrivateKey, X25519PrivateKey, X448PrivateKey]
KEMKey: TypeAlias = Union[KEMPublicKey, KEMPrivateKey]
