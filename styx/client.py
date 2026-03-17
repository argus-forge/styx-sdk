"""
StyxClient — public API for Styx encrypted messaging on XRPL.

Usage:
    from styx.client import StyxClient
    client = StyxClient(seed="sEd...", network="testnet")
    session_id = client.handshake("rRecipientAddress")
    tx_hash = client.send(session_id, "Hello, encrypted on XRPL")
    messages = client.receive(session_id)

    from styx.client import StyxAgentClient
    agent = StyxAgentClient(seed="sEd...", network="testnet")
    session_id = agent.handshake("rOtherAgent")
    agent.send_structured(session_id, {"command": "status"})
    responses = agent.receive_structured(session_id)
"""
from pathlib import Path
from typing import Dict, List, Optional

from styx.transport import StyxConfig, CredentialPolicy
from styx.transport.config import NETWORK_URLS
from styx.session.manager import StyxSession
from styx.session.agent import AgentSession
from styx.session.disclosure import generate_disclosure_key, export_disclosure, decrypt_with_disclosure
from styx.session.state import list_sessions


try:
    from xrpl.clients import JsonRpcClient
    from xrpl.wallet import Wallet
    _XRPL_AVAILABLE = True
except ImportError:
    _XRPL_AVAILABLE = False


def _make_wallet(seed: str):
    if not _XRPL_AVAILABLE:
        raise ImportError("xrpl-py is required: pip install xrpl-py")
    return Wallet.from_seed(seed)


def _make_client(network: str):
    if not _XRPL_AVAILABLE:
        raise ImportError("xrpl-py is required: pip install xrpl-py")
    url = NETWORK_URLS.get(network, NETWORK_URLS["testnet"])
    return JsonRpcClient(url)


class StyxClient:
    """
    Top-level public API. Default network: testnet.
    Patent Pending — Sentinel Intelligence LLC.
    TESTNET by default. Mainnet requires explicit configuration.
    """

    def __init__(
        self,
        seed: str = "",
        network: str = "testnet",
        state_dir: str = "~/.styx",
        credential_policy: Optional[dict] = None,
        _wallet=None,
        _client=None,
        _listener=None,
        _spk_registry=None,
    ) -> None:
        self.wallet = _wallet or _make_wallet(seed)
        self.client = _client or _make_client(network)
        self.config = StyxConfig(network=network, state_dir=state_dir)
        policy = None
        if credential_policy:
            policy = CredentialPolicy(
                required=credential_policy.get("required", False),
                credential_type=credential_policy.get("type"),
                issuer=credential_policy.get("issuer"),
            )
        self._session = StyxSession(
            self.wallet, self.client, self.config, policy, _listener, _spk_registry
        )
        self._sessions_dir = Path(state_dir).expanduser() / "sessions"

    def handshake(self, recipient_addr: str) -> str:
        return self._session.handshake_initiate(recipient_addr)

    def send(self, session_id: str, plaintext: str) -> str:
        return self._session.send(session_id, plaintext)

    def receive(self, session_id: str) -> List[dict]:
        return self._session.receive(session_id)

    def status(self, session_id: str) -> dict:
        return self._session.status(session_id)

    def publish_prekey(self) -> str:
        return self._session.publish_prekey()

    def export_disclosure(self, session_id: str, generations: List[int], output_path) -> None:
        export_disclosure(self._sessions_dir, session_id, generations, Path(output_path))

    def list_sessions(self) -> List[str]:
        return list_sessions(self._sessions_dir)


class StyxAgentClient(StyxClient):
    """Agent-mode client — structured JSON payloads, auto-rotation, no interactive prompts."""

    def __init__(
        self,
        seed: str = "",
        network: str = "testnet",
        state_dir: str = "~/.styx",
        credential_policy: Optional[dict] = None,
        _wallet=None,
        _client=None,
        _listener=None,
        _spk_registry=None,
    ) -> None:
        self.wallet = _wallet or _make_wallet(seed)
        self.client = _client or _make_client(network)
        self.config = StyxConfig(network=network, state_dir=state_dir)
        policy = None
        if credential_policy:
            policy = CredentialPolicy(
                required=credential_policy.get("required", False),
                credential_type=credential_policy.get("type"),
                issuer=credential_policy.get("issuer"),
            )
        self._session = AgentSession(
            self.wallet, self.client, self.config, policy, _listener, _spk_registry
        )
        self._sessions_dir = Path(state_dir).expanduser() / "sessions"

    def handshake(self, recipient_addr: str) -> str:
        return self._session.handshake_initiate(recipient_addr)

    def send_structured(self, session_id: str, payload: dict) -> str:
        return self._session.send_structured(session_id, payload)

    def receive_structured(self, session_id: str) -> List[dict]:
        return self._session.receive_structured(session_id)
