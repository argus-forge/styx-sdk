"""AgentSession — non-interactive agent-to-agent mode."""
import json
import time
from typing import Dict, List, Optional

from styx.exceptions import StyxAgentError
from styx.session.manager import StyxSession
from styx.transport import StyxConfig, CredentialPolicy


class AgentSession(StyxSession):
    """
    Non-interactive session for AI agent-to-agent communication.
    Auto-rotates SPK on every send. All payloads are structured JSON.
    No interactive prompts, no stdin, no blocking input().
    """

    def __init__(self, wallet, client, config: StyxConfig,
                 credential_policy=None, _listener=None, _spk_registry=None):
        super().__init__(wallet, client, config, credential_policy, _listener, _spk_registry)

    def _mark_agent_mode(self, session_id: str) -> None:
        from styx.session.state import load, save, state_path
        spath = state_path(self._sessions_dir, session_id)
        try:
            state = load(spath)
            state.agent_mode = True
            save(state, spath)
        except FileNotFoundError:
            pass

    def handshake_initiate(self, recipient_addr: str) -> str:
        session_id = super().handshake_initiate(recipient_addr)
        self._mark_agent_mode(session_id)
        return session_id

    def handshake_respond(self, handshake_msg) -> str:
        session_id = super().handshake_respond(handshake_msg)
        self._mark_agent_mode(session_id)
        return session_id

    def send_structured(self, session_id: str, payload: dict) -> str:
        """Serialize payload as JSON and send. Raises StyxAgentError if not serializable."""
        try:
            text = json.dumps(payload, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise StyxAgentError(f"Payload is not JSON-serializable: {exc}") from exc
        # Auto-rotate SPK before send (30-day window for agents)
        self.auto_rotate_spk(max_age_days=30)
        return self.send(session_id, text)

    def receive_structured(self, session_id: str) -> List[dict]:
        """Receive and parse structured JSON messages."""
        raw_messages = self.receive(session_id)
        results = []
        for msg in raw_messages:
            try:
                payload = json.loads(msg["plaintext"])
            except (json.JSONDecodeError, KeyError):
                payload = {"raw": msg.get("plaintext", "")}
            results.append({
                "payload": payload,
                "tx_hash": msg["tx_hash"],
                "ledger_index": msg["ledger_index"],
            })
        return results
