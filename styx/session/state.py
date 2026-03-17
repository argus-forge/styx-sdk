"""
Styx session state persistence.

SessionState captures all per-session data needed to resume an encrypted
conversation: ratchet state, skipped keys, counters, and metadata.

State is serialized to JSON with byte fields as hex strings.
File permissions are enforced to 0o600 (owner read/write only).
"""
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from styx.crypto import RatchetState, SkippedKeyManager
from styx.transport.credential import CredentialPolicy


def _session_id(addr_a: str, addr_b: str) -> str:
    """Deterministic session ID: SHA256 of sorted addresses."""
    pair = sorted([addr_a, addr_b])
    return hashlib.sha256(("".join(pair)).encode()).hexdigest()


@dataclass
class SessionState:
    """All per-conversation state needed to resume a Styx session."""
    session_id: str
    sender_addr: str
    recipient_addr: str
    ratchet_state: RatchetState
    skipped_keys: SkippedKeyManager
    n_messages_sent: int = 0
    n_messages_received: int = 0
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    agent_mode: bool = False
    spk_published_at: float = field(default_factory=time.time)
    credential_policy: Optional[CredentialPolicy] = None


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _bytes_or_none(v) -> Optional[str]:
    return v.hex() if isinstance(v, (bytes, bytearray)) else None


def _hex_or_none(s: Optional[str]) -> Optional[bytes]:
    return bytes.fromhex(s) if s else None


def _ratchet_to_dict(rs: RatchetState) -> dict:
    return {
        "root_key": rs.root_key.hex(),
        "chain_key_send": _bytes_or_none(rs.chain_key_send),
        "chain_key_recv": _bytes_or_none(rs.chain_key_recv),
        "dh_send": _bytes_or_none(rs.dh_send),
        "dh_send_pub": _bytes_or_none(rs.dh_send_pub),
        "dh_recv": _bytes_or_none(rs.dh_recv),
        "n_send": rs.n_send,
        "n_recv": rs.n_recv,
        "pn": rs.pn,
    }


def _ratchet_from_dict(d: dict) -> RatchetState:
    return RatchetState(
        root_key=bytes.fromhex(d["root_key"]),
        chain_key_send=_hex_or_none(d.get("chain_key_send")),
        chain_key_recv=_hex_or_none(d.get("chain_key_recv")),
        dh_send=_hex_or_none(d.get("dh_send")),
        dh_send_pub=_hex_or_none(d.get("dh_send_pub")),
        dh_recv=_hex_or_none(d.get("dh_recv")),
        n_send=d.get("n_send", 0),
        n_recv=d.get("n_recv", 0),
        pn=d.get("pn", 0),
    )


def _skipped_to_list(skm: SkippedKeyManager) -> list:
    """Serialize skipped key manager to list of [dh_pub_hex, n, mk_hex, ts] entries."""
    result = []
    for (dh_hex, n), (mk, ts) in skm._store.items():
        result.append([dh_hex, n, mk.hex(), ts])
    return result


def _skipped_from_list(entries: list) -> SkippedKeyManager:
    skm = SkippedKeyManager()
    for dh_hex, n, mk_hex, ts in entries:
        key = (dh_hex, n)
        skm._store[key] = (bytes.fromhex(mk_hex), ts)
    return skm


def _policy_to_dict(policy: Optional[CredentialPolicy]) -> Optional[dict]:
    if policy is None:
        return None
    return {
        "required": policy.required,
        "credential_type": policy.credential_type,
        "issuer": policy.issuer,
    }


def _policy_from_dict(d: Optional[dict]) -> Optional[CredentialPolicy]:
    if d is None:
        return None
    return CredentialPolicy(
        required=d.get("required", False),
        credential_type=d.get("credential_type"),
        issuer=d.get("issuer"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save(state: SessionState, path: Path) -> None:
    """
    Serialize SessionState to JSON at path.

    Private key bytes are stored as hex strings.
    File is written with mode 0o600 (owner read/write only).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "session_id": state.session_id,
        "sender_addr": state.sender_addr,
        "recipient_addr": state.recipient_addr,
        "ratchet_state": _ratchet_to_dict(state.ratchet_state),
        "skipped_keys": _skipped_to_list(state.skipped_keys),
        "n_messages_sent": state.n_messages_sent,
        "n_messages_received": state.n_messages_received,
        "created_at": state.created_at,
        "last_active": state.last_active,
        "agent_mode": state.agent_mode,
        "spk_published_at": state.spk_published_at,
        "credential_policy": _policy_to_dict(state.credential_policy),
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.rename(path)
    path.chmod(0o600)


def load(path: Path) -> SessionState:
    """
    Deserialize SessionState from JSON at path.

    Raises FileNotFoundError if path does not exist.
    Raises ValueError if state cannot be deserialized.
    """
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Corrupted session state at {path}: {exc}") from exc

    return SessionState(
        session_id=data["session_id"],
        sender_addr=data["sender_addr"],
        recipient_addr=data["recipient_addr"],
        ratchet_state=_ratchet_from_dict(data["ratchet_state"]),
        skipped_keys=_skipped_from_list(data.get("skipped_keys", [])),
        n_messages_sent=data.get("n_messages_sent", 0),
        n_messages_received=data.get("n_messages_received", 0),
        created_at=data.get("created_at", time.time()),
        last_active=data.get("last_active", time.time()),
        agent_mode=data.get("agent_mode", False),
        spk_published_at=data.get("spk_published_at", time.time()),
        credential_policy=_policy_from_dict(data.get("credential_policy")),
    )


def list_sessions(base_dir: Path) -> List[str]:
    """
    Return session_ids for all saved sessions in base_dir.

    Sessions are stored as {session_id}.json files.
    """
    if not base_dir.exists():
        return []
    return [p.stem for p in base_dir.glob("*.json") if p.is_file()]


def state_path(base_dir: Path, session_id: str) -> Path:
    """Return the canonical file path for a session state."""
    return base_dir / f"{session_id}.json"
