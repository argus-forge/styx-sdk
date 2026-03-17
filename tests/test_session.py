"""
Test suite for styx session management (STYX-SDK-03).
12 tests covering state, handshake, send/receive, agent mode, disclosure, credentials.
"""
import json
import os
import stat
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from styx.crypto import (
    generate_identity_key,
    generate_signed_prekey,
    generate_ephemeral_key,
    RatchetState,
    SkippedKeyManager,
    kdf_rk,
    kdf_ck,
    x3dh_initiator,
    x3dh_responder,
    sign_spk,
    dh_ratchet_step,
    symmetric_ratchet_step,
    encrypt,
    decrypt,
)
from styx.crypto.keys import ecdh
from styx.transport import StyxConfig, CredentialPolicy, StyxMessage
from styx.transport.memo import make_envelope, PROTOCOL_VERSION, build_memos, parse_memos
from styx.session.state import SessionState, save, load, list_sessions, state_path, _session_id
from styx.session.manager import StyxSession
from styx.session.agent import AgentSession
from styx.session.disclosure import (
    generate_disclosure_key,
    export_disclosure,
    decrypt_with_disclosure,
    save_root_history,
    load_root_history,
)
from styx.exceptions import (
    StyxHandshakeError,
    StyxDecryptionError,
    StyxSessionError,
    StyxCredentialError,
    StyxDisclosureError,
    StyxAgentError,
)
from styx.client import StyxClient, StyxAgentClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockWallet:
    def __init__(self, addr: str):
        self.classic_address = addr
        # Also expose .address for submit_styx_tx internals (uses wallet.address in AccountSet)
        self.address = addr


class MockClient:
    """Does nothing — just satisfies the interface."""
    pass


def make_config(tmp_dir: str) -> StyxConfig:
    return StyxConfig(network="testnet", state_dir=tmp_dir)


def make_session(addr: str, tmp_dir: str, spk_registry=None, listener=None) -> StyxSession:
    wallet = MockWallet(addr)
    client = MockClient()
    config = make_config(tmp_dir)
    return StyxSession(
        wallet, client, config,
        _listener=listener or MagicMock(),
        _spk_registry=spk_registry or {},
    )


def make_agent_session(addr: str, tmp_dir: str, spk_registry=None, listener=None) -> AgentSession:
    wallet = MockWallet(addr)
    client = MockClient()
    config = make_config(tmp_dir)
    return AgentSession(
        wallet, client, config,
        _listener=listener or MagicMock(),
        _spk_registry=spk_registry or {},
    )


def setup_session_pair(alice_tmp: str, bob_tmp: str):
    """
    Creates alice and bob sessions, performs handshake.
    Returns (alice_session, bob_session, session_id).
    """
    alice_addr = "rALICEtest1111111111111111111111"
    bob_addr = "rBOBtest22222222222222222222222222"

    # Build bob's SPK so alice can find it via _spk_registry
    bob_ik = generate_identity_key()
    bob_spk = generate_signed_prekey()

    # Alice's _spk_registry maps bob_addr -> bob_spk.public
    alice_mock_listener = MagicMock()
    alice_mock_listener.poll.return_value = []
    bob_mock_listener = MagicMock()
    bob_mock_listener.poll.return_value = []

    spk_registry_for_alice = {bob_addr: bob_spk.public}

    alice_wallet = MockWallet(alice_addr)
    bob_wallet = MockWallet(bob_addr)
    alice_client = MockClient()
    bob_client = MockClient()

    alice_config = make_config(alice_tmp)
    bob_config = make_config(bob_tmp)

    # Patch submit so handshake doesn't need real XRPL
    with patch("styx.session.manager.submit_styx_tx") as mock_submit:
        mock_submit.return_value = "mock_tx_hash_hs"

        alice_session = StyxSession(
            alice_wallet, alice_client, alice_config,
            _listener=alice_mock_listener,
            _spk_registry=spk_registry_for_alice,
        )

        # Bob's session needs its own SPK to match what alice fetched
        # We inject by pre-creating bob's spk.json to match bob_spk
        bob_keys_dir = Path(bob_tmp) / "keys" / bob_addr
        bob_keys_dir.mkdir(parents=True, exist_ok=True)
        bob_spk_sig = sign_spk(bob_ik.private, bob_spk.public, bob_addr)
        spk_data = {
            "private_hex": bob_spk.private.hex(),
            "public_hex": bob_spk.public.hex(),
            "sig_hex": bob_spk_sig.hex(),
            "created_at": time.time(),
        }
        (bob_keys_dir / "spk.json").write_text(json.dumps(spk_data))
        (bob_keys_dir / "spk.json").chmod(0o600)
        # Also inject bob's ik
        ik_data = {
            "private_hex": bob_ik.private.hex(),
            "public_hex": bob_ik.public.hex(),
            "created_at": time.time(),
        }
        (bob_keys_dir / "ik.json").write_text(json.dumps(ik_data))
        (bob_keys_dir / "ik.json").chmod(0o600)

        bob_session = StyxSession(
            bob_wallet, bob_client, bob_config,
            _listener=bob_mock_listener,
            _spk_registry={},
        )

        # Capture alice's HS_INIT envelope
        captured_memos = []
        original_submit = mock_submit.side_effect

        def capture_submit(wallet, client, memos, config):
            captured_memos.append(memos)
            return "mock_tx_hash_hs"

        mock_submit.side_effect = capture_submit

        session_id = alice_session.handshake_initiate(bob_addr)

        # Parse the captured HS_INIT envelope
        assert len(captured_memos) >= 1
        hs_memos = captured_memos[0]
        envelope = parse_memos(hs_memos)
        assert envelope is not None
        assert envelope["t"] == "HS_INIT"

        hs_msg = StyxMessage(
            envelope=envelope,
            tx_hash="mock_hs_tx",
            ledger_index=1000,
            timestamp=time.time(),
            sender=alice_addr,
        )

        bob_session_id = bob_session.handshake_respond(hs_msg)

    # Both should have the same session_id
    assert session_id == bob_session_id

    return alice_session, bob_session, session_id


# ---------------------------------------------------------------------------
# Test 1: Session state save/load round-trip
# ---------------------------------------------------------------------------

def test_session_state_save_load():
    """SessionState serializes and deserializes byte-for-byte correctly."""
    with tempfile.TemporaryDirectory() as tmp:
        sessions_dir = Path(tmp) / "sessions"
        sessions_dir.mkdir()

        ik = generate_identity_key()
        ek = generate_ephemeral_key()
        rk = os.urandom(32)
        ck_s = os.urandom(32)
        ck_r = os.urandom(32)

        rs = RatchetState(
            root_key=rk,
            chain_key_send=ck_s,
            chain_key_recv=ck_r,
            dh_send=ik.private,
            dh_send_pub=ik.public,
            dh_recv=ek.public,
            n_send=5,
            n_recv=3,
            pn=2,
        )
        skm = SkippedKeyManager()
        skm.store(ek.public, 7, os.urandom(32))

        sid = "deadbeef" * 8
        state = SessionState(
            session_id=sid,
            sender_addr="rALICE",
            recipient_addr="rBOB",
            ratchet_state=rs,
            skipped_keys=skm,
            n_messages_sent=10,
            n_messages_received=8,
        )

        spath = state_path(sessions_dir, sid)
        save(state, spath)
        loaded = load(spath)

        assert loaded.session_id == sid
        assert loaded.ratchet_state.root_key == rk
        assert loaded.ratchet_state.chain_key_send == ck_s
        assert loaded.ratchet_state.chain_key_recv == ck_r
        assert loaded.ratchet_state.dh_send == ik.private
        assert loaded.ratchet_state.dh_send_pub == ik.public
        assert loaded.ratchet_state.dh_recv == ek.public
        assert loaded.ratchet_state.n_send == 5
        assert loaded.ratchet_state.n_recv == 3
        assert loaded.ratchet_state.pn == 2
        assert loaded.n_messages_sent == 10
        assert loaded.n_messages_received == 8


# ---------------------------------------------------------------------------
# Test 2: Full handshake — initiator + responder derive same SK
# ---------------------------------------------------------------------------

def test_handshake_shared_secret():
    """After handshake, alice.chain_key_send == bob.chain_key_recv."""
    with tempfile.TemporaryDirectory() as alice_tmp, \
         tempfile.TemporaryDirectory() as bob_tmp:

        alice_session, bob_session, session_id = setup_session_pair(alice_tmp, bob_tmp)

        alice_spath = state_path(
            Path(alice_tmp) / "sessions", session_id
        )
        bob_spath = state_path(
            Path(bob_tmp) / "sessions", session_id
        )

        alice_state = load(alice_spath)
        bob_state = load(bob_spath)

        # Alice has chain_key_send; Bob has chain_key_recv
        assert alice_state.ratchet_state.chain_key_send is not None
        assert bob_state.ratchet_state.chain_key_recv is not None
        assert alice_state.ratchet_state.chain_key_send == bob_state.ratchet_state.chain_key_recv


# ---------------------------------------------------------------------------
# Test 3: Send/receive mock
# ---------------------------------------------------------------------------

def test_send_receive():
    """alice.send() -> bob.receive() returns the plaintext."""
    with tempfile.TemporaryDirectory() as alice_tmp, \
         tempfile.TemporaryDirectory() as bob_tmp:

        alice_session, bob_session, session_id = setup_session_pair(alice_tmp, bob_tmp)

        alice_addr = "rALICEtest1111111111111111111111"
        bob_addr = "rBOBtest22222222222222222222222222"

        captured_memos = []

        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.side_effect = lambda w, c, m, cfg: captured_memos.append(m) or "mock_data_tx"
            alice_session.send(session_id, "hello world")

        # Parse the DATA envelope alice sent
        assert len(captured_memos) >= 1
        data_memos = captured_memos[0]
        envelope = parse_memos(data_memos)
        assert envelope is not None
        assert envelope["t"] == "DATA"

        data_msg = StyxMessage(
            envelope=envelope,
            tx_hash="mock_data_tx",
            ledger_index=1001,
            timestamp=time.time(),
            sender=alice_addr,
        )

        # Bob's listener returns this message
        bob_session._listener.poll.return_value = [data_msg]

        with patch("styx.session.manager.submit_styx_tx"):
            results = bob_session.receive(session_id)

        assert len(results) == 1
        assert results[0]["plaintext"] == "hello world"
        assert results[0]["tx_hash"] == "mock_data_tx"


# ---------------------------------------------------------------------------
# Test 4: Agent mode structured send/receive
# ---------------------------------------------------------------------------

def test_agent_structured_send_receive():
    """AgentSession send_structured/receive_structured round-trips JSON."""
    with tempfile.TemporaryDirectory() as alice_tmp, \
         tempfile.TemporaryDirectory() as bob_tmp:

        alice_addr = "rALICEtest1111111111111111111111"
        bob_addr = "rBOBtest22222222222222222222222222"

        bob_ik = generate_identity_key()
        bob_spk = generate_signed_prekey()
        bob_spk_sig = sign_spk(bob_ik.private, bob_spk.public, bob_addr)

        # Pre-create bob's keys
        bob_keys_dir = Path(bob_tmp) / "keys" / bob_addr
        bob_keys_dir.mkdir(parents=True, exist_ok=True)
        (bob_keys_dir / "ik.json").write_text(json.dumps({
            "private_hex": bob_ik.private.hex(),
            "public_hex": bob_ik.public.hex(),
            "created_at": time.time(),
        }))
        (bob_keys_dir / "ik.json").chmod(0o600)
        (bob_keys_dir / "spk.json").write_text(json.dumps({
            "private_hex": bob_spk.private.hex(),
            "public_hex": bob_spk.public.hex(),
            "sig_hex": bob_spk_sig.hex(),
            "created_at": time.time(),
        }))
        (bob_keys_dir / "spk.json").chmod(0o600)

        captured_memos = []

        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            def capture(w, c, m, cfg):
                captured_memos.append(m)
                return "mock_tx"

            mock_submit.side_effect = capture

            alice_session = make_agent_session(
                alice_addr, alice_tmp,
                spk_registry={bob_addr: bob_spk.public},
            )
            bob_session = make_agent_session(bob_addr, bob_tmp)

            session_id = alice_session.handshake_initiate(bob_addr)

            # Get HS_INIT
            hs_memos = captured_memos[0]
            hs_env = parse_memos(hs_memos)
            hs_msg = StyxMessage(
                envelope=hs_env,
                tx_hash="hs_tx",
                ledger_index=1000,
                timestamp=time.time(),
                sender=alice_addr,
            )
            bob_session.handshake_respond(hs_msg)

        # Now do structured send
        captured_memos.clear()
        payload = {"cmd": "ping", "id": 42}

        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.side_effect = lambda w, c, m, cfg: captured_memos.append(m) or "data_tx"
            alice_session.send_structured(session_id, payload)

        data_env = parse_memos(captured_memos[0])
        data_msg = StyxMessage(
            envelope=data_env,
            tx_hash="data_tx",
            ledger_index=1001,
            timestamp=time.time(),
            sender=alice_addr,
        )
        bob_session._listener.poll.return_value = [data_msg]

        with patch("styx.session.manager.submit_styx_tx"):
            results = bob_session.receive_structured(session_id)

        assert len(results) == 1
        assert results[0]["payload"] == {"cmd": "ping", "id": 42}


# ---------------------------------------------------------------------------
# Test 5: Agent/human interop
# ---------------------------------------------------------------------------

def test_agent_human_interop():
    """AgentSession and StyxSession can exchange messages in both directions."""
    with tempfile.TemporaryDirectory() as alice_tmp, \
         tempfile.TemporaryDirectory() as bob_tmp:

        alice_addr = "rALICEtest1111111111111111111111"
        bob_addr = "rBOBtest22222222222222222222222222"

        bob_ik = generate_identity_key()
        bob_spk = generate_signed_prekey()
        bob_spk_sig = sign_spk(bob_ik.private, bob_spk.public, bob_addr)

        bob_keys_dir = Path(bob_tmp) / "keys" / bob_addr
        bob_keys_dir.mkdir(parents=True, exist_ok=True)
        (bob_keys_dir / "ik.json").write_text(json.dumps({
            "private_hex": bob_ik.private.hex(),
            "public_hex": bob_ik.public.hex(),
            "created_at": time.time(),
        }))
        (bob_keys_dir / "ik.json").chmod(0o600)
        (bob_keys_dir / "spk.json").write_text(json.dumps({
            "private_hex": bob_spk.private.hex(),
            "public_hex": bob_spk.public.hex(),
            "sig_hex": bob_spk_sig.hex(),
            "created_at": time.time(),
        }))
        (bob_keys_dir / "spk.json").chmod(0o600)

        captured_memos = []

        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.side_effect = lambda w, c, m, cfg: captured_memos.append(m) or "tx"

            # Alice is agent, Bob is regular session
            alice_session = make_agent_session(
                alice_addr, alice_tmp,
                spk_registry={bob_addr: bob_spk.public},
            )
            bob_session = make_session(bob_addr, bob_tmp)

            session_id = alice_session.handshake_initiate(bob_addr)
            hs_env = parse_memos(captured_memos[0])
            hs_msg = StyxMessage(
                envelope=hs_env,
                tx_hash="hs_tx",
                ledger_index=1000,
                timestamp=time.time(),
                sender=alice_addr,
            )
            bob_session.handshake_respond(hs_msg)

        # Alice sends structured
        captured_memos.clear()
        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.side_effect = lambda w, c, m, cfg: captured_memos.append(m) or "tx"
            alice_session.send_structured(session_id, {"msg": "from agent"})

        data_env = parse_memos(captured_memos[0])
        data_msg = StyxMessage(
            envelope=data_env,
            tx_hash="data_tx",
            ledger_index=1001,
            timestamp=time.time(),
            sender=alice_addr,
        )
        bob_session._listener.poll.return_value = [data_msg]

        with patch("styx.session.manager.submit_styx_tx"):
            bob_results = bob_session.receive(session_id)

        assert len(bob_results) == 1
        assert json.loads(bob_results[0]["plaintext"]) == {"msg": "from agent"}

        # Bob replies as human
        captured_memos.clear()
        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.side_effect = lambda w, c, m, cfg: captured_memos.append(m) or "tx2"
            bob_session.send(session_id, '{"reply": "from human"}')

        reply_env = parse_memos(captured_memos[0])
        reply_msg = StyxMessage(
            envelope=reply_env,
            tx_hash="reply_tx",
            ledger_index=1002,
            timestamp=time.time(),
            sender=bob_addr,
        )
        alice_session._listener.poll.return_value = [reply_msg]

        with patch("styx.session.manager.submit_styx_tx"):
            alice_results = alice_session.receive_structured(session_id)

        assert len(alice_results) == 1
        assert alice_results[0]["payload"] == {"reply": "from human"}


# ---------------------------------------------------------------------------
# Test 6: SPK auto-rotation
# ---------------------------------------------------------------------------

def test_auto_rotate_spk():
    """auto_rotate_spk rotates and publishes when SPK is old enough."""
    with tempfile.TemporaryDirectory() as tmp:
        session = make_session("rALICEtest1111111111111111111111", tmp)
        # Backdate SPK creation to 70 days ago
        session._spk_created_at = time.time() - (70 * 86400)

        with patch("styx.session.manager.submit_styx_tx") as mock_submit:
            mock_submit.return_value = "rotation_tx_hash"
            result = session.auto_rotate_spk(max_age_days=60)

        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Test 7: Disclosure key derivation and decryption
# ---------------------------------------------------------------------------

def test_disclosure_key_derivation_and_decryption():
    """Disclosure key from generation 0 can decrypt data encrypted with that key."""
    from Crypto.Cipher import AES

    with tempfile.TemporaryDirectory() as tmp:
        sessions_dir = Path(tmp) / "sessions"
        sessions_dir.mkdir()
        session_id = "aabbcc" * 10 + "aabb"

        root_key = os.urandom(32)
        save_root_history(sessions_dir, session_id, {0: root_key})

        dk = generate_disclosure_key(sessions_dir, session_id, 0)
        assert len(dk) == 32

        # Encrypt with dk
        nonce = os.urandom(12)
        ad = b"test-ad"
        plaintext = b"secret compliance data"

        cipher = AES.new(dk, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        ct, tag = cipher.encrypt_and_digest(plaintext)

        # Decrypt with disclosure key
        recovered = decrypt_with_disclosure(dk, ct, nonce, tag, ad)
        assert recovered == plaintext


# ---------------------------------------------------------------------------
# Test 8: Disclosure key scoping — wrong generation fails
# ---------------------------------------------------------------------------

def test_disclosure_key_scoping():
    """Disclosure key for generation 0 cannot decrypt data encrypted with generation 2 key."""
    from Crypto.Cipher import AES

    with tempfile.TemporaryDirectory() as tmp:
        sessions_dir = Path(tmp) / "sessions"
        sessions_dir.mkdir()
        session_id = "deadbeef" * 8

        rk0 = os.urandom(32)
        rk2 = os.urandom(32)
        # Ensure they are different
        while rk2 == rk0:
            rk2 = os.urandom(32)

        save_root_history(sessions_dir, session_id, {0: rk0, 2: rk2})

        dk0 = generate_disclosure_key(sessions_dir, session_id, 0)
        dk2 = generate_disclosure_key(sessions_dir, session_id, 2)
        assert dk0 != dk2

        # Encrypt with dk2
        nonce = os.urandom(12)
        ad = b"scoped-ad"
        plaintext = b"generation 2 secret"

        cipher = AES.new(dk2, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        ct, tag = cipher.encrypt_and_digest(plaintext)

        # Attempt decryption with dk0 should fail
        with pytest.raises(StyxDisclosureError):
            decrypt_with_disclosure(dk0, ct, nonce, tag, ad)


# ---------------------------------------------------------------------------
# Test 9: Disclosure export contains no private keys
# ---------------------------------------------------------------------------

def test_disclosure_export_no_private_keys():
    """export_disclosure output file must not contain any private key fields."""
    with tempfile.TemporaryDirectory() as tmp:
        sessions_dir = Path(tmp) / "sessions"
        sessions_dir.mkdir()
        session_id = "cafebabe" * 8

        root_key = os.urandom(32)
        save_root_history(sessions_dir, session_id, {0: root_key})

        output_path = Path(tmp) / "audit_keys.json"
        export_disclosure(sessions_dir, session_id, [0], output_path)

        content = output_path.read_text()

        # Must NOT contain private key fields
        for forbidden in ("private_hex", "ik_private", "spk_private", "dh_send", "chain_key"):
            assert forbidden not in content, f"Found forbidden field: {forbidden}"

        # Must contain the disclosure key
        assert "key_hex" in content

        # File permissions must be 0o600
        file_mode = stat.S_IMODE(output_path.stat().st_mode)
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"


# ---------------------------------------------------------------------------
# Test 10: Credential gate
# ---------------------------------------------------------------------------

def test_credential_gate():
    """Handshake raises StyxCredentialError when credential policy is not met."""
    with tempfile.TemporaryDirectory() as tmp:
        addr = "rALICEtest1111111111111111111111"
        bob_addr = "rBOBtest22222222222222222222222222"

        bob_spk = generate_signed_prekey()

        policy = CredentialPolicy(
            required=True,
            credential_type="KYC_VERIFIED",
            issuer="rIssuerAddr",
        )

        wallet = MockWallet(addr)
        client = MockClient()
        config = make_config(tmp)

        session = StyxSession(
            wallet, client, config,
            credential_policy=policy,
            _listener=MagicMock(),
            _spk_registry={bob_addr: bob_spk.public},
        )

        with patch("styx.session.manager.require_credential") as mock_cred:
            mock_cred.side_effect = StyxCredentialError("No valid credential found")
            with pytest.raises(StyxCredentialError):
                session.handshake_initiate(bob_addr)


# ---------------------------------------------------------------------------
# Test 11: Session listing
# ---------------------------------------------------------------------------

def test_session_listing():
    """list_sessions returns all saved session IDs."""
    with tempfile.TemporaryDirectory() as tmp:
        sessions_dir = Path(tmp) / "sessions"
        sessions_dir.mkdir()

        session_ids = ["aaa111", "bbb222", "ccc333"]

        for sid in session_ids:
            ik = generate_identity_key()
            rs = RatchetState(
                root_key=os.urandom(32),
                dh_send=ik.private,
                dh_send_pub=ik.public,
            )
            state = SessionState(
                session_id=sid,
                sender_addr="rALICE",
                recipient_addr="rBOB",
                ratchet_state=rs,
                skipped_keys=SkippedKeyManager(),
            )
            spath = state_path(sessions_dir, sid)
            save(state, spath)

        result = list_sessions(sessions_dir)
        assert set(result) == set(session_ids)


# ---------------------------------------------------------------------------
# Test 12: StyxClient API surface
# ---------------------------------------------------------------------------

def test_styx_client_api_surface():
    """StyxClient exposes required methods."""
    with tempfile.TemporaryDirectory() as tmp:
        wallet = MockWallet("rALICEtest1111111111111111111111")
        client = MockClient()

        c = StyxClient(
            _wallet=wallet,
            _client=client,
            _listener=MagicMock(),
        )

        required_methods = [
            "handshake",
            "send",
            "receive",
            "status",
            "publish_prekey",
            "export_disclosure",
        ]

        for method_name in required_methods:
            assert hasattr(c, method_name), f"Missing attribute: {method_name}"
            assert callable(getattr(c, method_name)), f"Not callable: {method_name}"
