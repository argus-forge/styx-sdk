"""
Styx Double Ratchet state and step functions.
"""
from dataclasses import dataclass, field
from typing import Optional

from .keys import ecdh, generate_ephemeral_key, StyxKeyPair
from .kdf import kdf_rk, kdf_ck

MAX_SKIP = 100


@dataclass
class RatchetState:
    """Per-conversation Double Ratchet state."""
    root_key: bytes
    chain_key_send: Optional[bytes] = None
    chain_key_recv: Optional[bytes] = None
    # dh_send: 32-byte private key bytes of current sending ratchet keypair
    dh_send: Optional[bytes] = None
    # dh_send_pub: 33-byte compressed public of sending ratchet
    dh_send_pub: Optional[bytes] = None
    # dh_recv: 33-byte compressed public of remote ratchet key
    dh_recv: Optional[bytes] = None
    n_send: int = 0
    n_recv: int = 0
    pn: int = 0


def dh_ratchet_step(state: RatchetState, dh_received_pub: bytes) -> RatchetState:
    """
    Perform a full DH ratchet step upon receiving a new peer ratchet key.

    Advances root key twice:
      1. (RK, CKr) = KDF_RK(RK, ECDH(DHs, dh_received_pub))
      2. Generate new DHs
      3. (RK, CKs) = KDF_RK(RK, ECDH(new_DHs, dh_received_pub))

    Returns a new RatchetState with updated keys.
    """
    # Step 1: derive new receive chain
    shared1 = ecdh(state.dh_send, dh_received_pub)
    new_rk1, new_ckr = kdf_rk(state.root_key, shared1)

    # Step 2: generate new sending ratchet
    new_dhs = generate_ephemeral_key()

    # Step 3: derive new send chain
    shared2 = ecdh(new_dhs.private, dh_received_pub)
    new_rk2, new_cks = kdf_rk(new_rk1, shared2)

    return RatchetState(
        root_key=new_rk2,
        chain_key_send=new_cks,
        chain_key_recv=new_ckr,
        dh_send=new_dhs.private,
        dh_send_pub=new_dhs.public,
        dh_recv=dh_received_pub,
        n_send=0,
        n_recv=0,
        pn=state.n_send,
    )


def symmetric_ratchet_step(chain_key: bytes) -> tuple:
    """
    Advance the symmetric ratchet one step.

    Returns (new_chain_key, message_key) — 32 bytes each.
    """
    return kdf_ck(chain_key)
