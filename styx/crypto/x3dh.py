"""
Styx X3DH handshake — initiator and responder sides.
IK-to-SPK binding signature (ECDSA).
"""
import hashlib

from ecpy.curves import Curve
from ecpy.keys import ECPrivateKey, ECPublicKey
from ecpy.ecdsa import ECDSA

from .keys import StyxKeyPair, ecdh, _load_public, _private_int, _curve
from .kdf import initial_sk

_signer = ECDSA()


# ---------------------------------------------------------------------------
# DER helpers (ECPy returns DER-encoded ECDSA signatures)
# ---------------------------------------------------------------------------

def _der_decode(der: bytes):
    """Parse DER-encoded ECDSA signature into (r, s) integers."""
    assert der[0] == 0x30, "Expected DER SEQUENCE"
    idx = 2
    assert der[idx] == 0x02, "Expected INTEGER r"
    rlen = der[idx + 1]
    r = int.from_bytes(der[idx + 2: idx + 2 + rlen], "big")
    idx += 2 + rlen
    assert der[idx] == 0x02, "Expected INTEGER s"
    slen = der[idx + 1]
    s = int.from_bytes(der[idx + 2: idx + 2 + slen], "big")
    return r, s


def _der_encode(r: int, s: int) -> bytes:
    """Encode (r, s) integers into DER SEQUENCE for ECPy verification."""
    def enc_int(n: int) -> bytes:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    body = enc_int(r) + enc_int(s)
    return b"\x30" + bytes([len(body)]) + body


# ---------------------------------------------------------------------------
# X3DH
# ---------------------------------------------------------------------------

def x3dh_initiator(
    ik_sender: StyxKeyPair,
    ek_sender: StyxKeyPair,
    spk_recipient_pub: bytes,
    ik_recipient_pub: bytes | None,
    sender_addr: str,
    recipient_addr: str,
) -> bytes:
    """
    Compute SK from initiator side.

    Case A (first contact): ik_recipient_pub=None — DH1 || DH2 only.
    Case B (known peer):    ik_recipient_pub set — DH1 || DH2 || DH3.

    Returns SK (32 bytes).
    """
    dh1 = ecdh(ik_sender.private, spk_recipient_pub)
    dh2 = ecdh(ek_sender.private, spk_recipient_pub)
    components = [dh1, dh2]
    if ik_recipient_pub is not None:
        dh3 = ecdh(ek_sender.private, ik_recipient_pub)
        components.append(dh3)
    return initial_sk(components, sender_addr, recipient_addr)


def x3dh_responder(
    ik_responder: StyxKeyPair,
    spk_responder: StyxKeyPair,
    ik_sender_pub: bytes,
    ek_sender_pub: bytes,
    sender_addr: str,
    recipient_addr: str,
) -> bytes:
    """
    Compute SK from responder side (mirrors initiator).

    DH1 = ECDH(SPK_b, IK_a)
    DH2 = ECDH(SPK_b, E_a)
    Returns SK (32 bytes). For Case A only (no DH3 mirror).
    """
    dh1 = ecdh(spk_responder.private, ik_sender_pub)
    dh2 = ecdh(spk_responder.private, ek_sender_pub)
    return initial_sk([dh1, dh2], sender_addr, recipient_addr)


def sign_spk(
    ik_private: bytes,
    spk_public: bytes,
    recipient_addr: str,
) -> bytes:
    """
    Sign SPK binding: ECDSA(IK.priv, SHA256(SPK.pub || recipient_r_address)).

    Returns 64-byte raw signature: r || s (32 bytes each).
    """
    sig_input = spk_public + recipient_addr.encode()
    sig_hash = hashlib.sha256(sig_input).digest()
    priv_key = ECPrivateKey(_private_int(ik_private), _curve)
    sig_der = _signer.sign(sig_hash, priv_key)
    r, s = _der_decode(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_spk_sig(
    ik_public: bytes,
    spk_public: bytes,
    recipient_addr: str,
    sig: bytes,
) -> bool:
    """
    Verify IK-to-SPK binding signature.

    sig: 64-byte raw r || s.
    Returns True if valid, False otherwise.
    """
    sig_input = spk_public + recipient_addr.encode()
    sig_hash = hashlib.sha256(sig_input).digest()
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    sig_der = _der_encode(r, s)
    pub_key = _load_public(ik_public)
    try:
        return _signer.verify(sig_hash, sig_der, pub_key)
    except Exception:
        return False
