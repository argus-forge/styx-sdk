"""
Styx key generation and ECDH — secp256k1 via ECPy.
All private keys: 32-byte raw bytes. Public keys: 33-byte compressed.
"""
import os

from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey, ECPublicKey

_curve = Curve.get_curve("secp256k1")


class StyxKeyPair:
    """A secp256k1 keypair with 32-byte private and 33-byte compressed public."""

    def __init__(self, private: bytes, public: bytes) -> None:
        assert len(private) == 32, "private key must be 32 bytes"
        assert len(public) == 33, "public key must be 33 bytes (compressed)"
        self.private: bytes = private
        self.public: bytes = public

    @property
    def public_hex(self) -> str:
        return self.public.hex()

    def __repr__(self) -> str:
        return f"StyxKeyPair(pub={self.public_hex[:16]}...)"


def _compress_point(point) -> bytes:
    prefix = b"\x02" if point.y % 2 == 0 else b"\x03"
    return prefix + point.x.to_bytes(32, "big")


def _load_public(pub_bytes: bytes) -> ECPublicKey:
    """Load a 33-byte compressed public key into an ECPy ECPublicKey."""
    point = _curve.decode_point(pub_bytes)
    return ECPublicKey(point)


def _private_int(priv_bytes: bytes) -> int:
    return int.from_bytes(priv_bytes, "big")


def ecdh(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    """Compute ECDH shared secret. Returns 32-byte x-coordinate of shared point."""
    priv_int = _private_int(priv_bytes)
    peer_pub = _load_public(peer_pub_bytes)
    shared_point = priv_int * peer_pub.W
    return shared_point.x.to_bytes(32, "big")


def validate_public_key(pub_bytes: bytes) -> bool:
    """Return True if pub_bytes is a valid compressed secp256k1 point."""
    if len(pub_bytes) != 33:
        return False
    if pub_bytes[0] not in (0x02, 0x03):
        return False
    try:
        point = _curve.decode_point(pub_bytes)
        # Verify the reconstructed point re-encodes to the same bytes
        reencoded = _compress_point(point)
        return reencoded == pub_bytes
    except Exception:
        return False


def _generate_keypair() -> StyxKeyPair:
    order = _curve.order
    while True:
        priv_bytes = os.urandom(32)
        priv_int = int.from_bytes(priv_bytes, "big")
        if 0 < priv_int < order:
            break
    priv_key = ECPrivateKey(priv_int, _curve)
    pub_point = priv_key.get_public_key().W
    pub_bytes = _compress_point(pub_point)
    return StyxKeyPair(priv_bytes, pub_bytes)


def generate_identity_key() -> StyxKeyPair:
    """Generate a long-term identity key (IK)."""
    return _generate_keypair()


def generate_signed_prekey() -> StyxKeyPair:
    """Generate a signed prekey (SPK, rotated every 30–90 days)."""
    return _generate_keypair()


def generate_ephemeral_key() -> StyxKeyPair:
    """Generate a single-use ephemeral key (EK)."""
    return _generate_keypair()
