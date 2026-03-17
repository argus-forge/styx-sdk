"""
Selective disclosure — compliance key derivation and export.
Disclosure keys are derived from root keys at specific ratchet generations.
They are ONE-WAY and SCOPED: cannot derive identity/SPK keys or earlier state.
"""
import json
import os
from pathlib import Path
from typing import List

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

from styx.exceptions import StyxDisclosureError


_DISCLOSURE_SALT = b"StyxDisclose"
_PRIVATE_KEY_FIELDS = {"private_hex", "ik_private", "spk_private", "dh_send"}


def _roots_path(sessions_dir: Path, session_id: str) -> Path:
    return sessions_dir / f"{session_id}_roots.json"


def load_root_history(sessions_dir: Path, session_id: str) -> dict:
    """Load {generation_str: root_key_hex} dict from disk."""
    p = _roots_path(sessions_dir, session_id)
    if not p.exists():
        return {}
    d = json.loads(p.read_text())
    return d.get("roots", {})


def save_root_history(sessions_dir: Path, session_id: str, roots: dict) -> None:
    """Save root key history. roots: {generation_int: root_key_bytes}"""
    p = _roots_path(sessions_dir, session_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    serialized = {str(k): (v.hex() if isinstance(v, bytes) else v) for k, v in roots.items()}
    p.write_text(json.dumps({"session_id": session_id, "roots": serialized}, indent=2))
    p.chmod(0o600)


def generate_disclosure_key(sessions_dir: Path, session_id: str, generation: int) -> bytes:
    """
    Derive a 32-byte disclosure key for the given ratchet generation.
    HKDF(salt='StyxDisclose', ikm=root_key_at_generation, info=session_id||generation_bytes, length=32).
    Raises StyxDisclosureError if root key for generation not found.
    """
    roots = load_root_history(sessions_dir, session_id)
    root_key_hex = roots.get(str(generation))
    if root_key_hex is None:
        raise StyxDisclosureError(
            f"Root key for session {session_id} generation {generation} not found"
        )
    root_key = bytes.fromhex(root_key_hex)
    info = session_id.encode() + generation.to_bytes(4, "big")
    return HKDF(
        master=root_key,
        key_len=32,
        salt=_DISCLOSURE_SALT,
        hashmod=SHA256,
        num_keys=1,
        context=info,
    )


def export_disclosure(sessions_dir: Path, session_id: str, generations: List[int], output_path: Path) -> None:
    """
    Export disclosure keys for specified generations to output_path.
    Output JSON: {"session_id": str, "disclosures": [{"generation": int, "key_hex": str}]}
    File mode: 0o600.
    NEVER writes identity keys, SPK private keys, or full ratchet state.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    disclosures = []
    for gen in generations:
        dk = generate_disclosure_key(sessions_dir, session_id, gen)
        disclosures.append({"generation": gen, "key_hex": dk.hex()})

    payload = {"session_id": session_id, "disclosures": disclosures}
    output_path.write_text(json.dumps(payload, indent=2))
    output_path.chmod(0o600)


def decrypt_with_disclosure(
    disclosure_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    ad: bytes,
) -> bytes:
    """
    AES-256-GCM decrypt using a disclosure key.
    Raises StyxDisclosureError if authentication fails (wrong key / wrong generation).
    """
    try:
        cipher = AES.new(disclosure_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise StyxDisclosureError("Disclosure key authentication failed — wrong generation or session") from exc
