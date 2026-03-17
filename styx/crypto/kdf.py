"""
Styx KDF functions per PROTOCOL.md.

KDF_RK: Single HKDF-SHA256 call (RFC 5869). Do NOT manually pre-hash.
KDF_CK: HMAC-SHA256 per Signal construction.
"""
import hashlib
import hmac as _hmac

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple:
    """
    Root key ratchet (KDF_RK).

    Single HKDF call: salt=root_key, ikm=dh_output, info='StyxRoot', length=64.
    Returns (new_root_key, chain_key) — 32 bytes each.
    """
    output: bytes = HKDF(
        master=dh_output,
        key_len=64,
        salt=root_key,
        hashmod=SHA256,
        num_keys=1,
        context=b"StyxRoot",
    )
    return output[:32], output[32:]


def kdf_ck(chain_key: bytes) -> tuple:
    """
    Symmetric chain ratchet (KDF_CK). Matches Signal exactly.

    Returns (new_chain_key, message_key) — 32 bytes each.
    """
    mk = _hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    new_ck = _hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return new_ck, mk


def initial_sk(dh_components: list, sender_addr: str, recipient_addr: str) -> bytes:
    """
    Derive initial shared key SK from handshake DH outputs.

    HKDF(salt=0x00*32, ikm=DH1||DH2[||DH3], info='StyxInit'||sender||recipient, length=32).
    """
    ikm = b"".join(dh_components)
    info = b"StyxInit" + sender_addr.encode() + recipient_addr.encode()
    return HKDF(
        master=ikm,
        key_len=32,
        salt=b"\x00" * 32,
        hashmod=SHA256,
        num_keys=1,
        context=info,
    )
