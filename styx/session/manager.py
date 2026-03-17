"""
StyxSession — core session manager for Double Ratchet encrypted messaging on XRPL.
"""
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from styx.crypto import (
    RatchetState,
    SkippedKeyManager,
    StyxKeyPair,
    generate_identity_key,
    generate_signed_prekey,
    generate_ephemeral_key,
    x3dh_initiator,
    x3dh_responder,
    sign_spk,
    kdf_rk,
    kdf_ck,
    dh_ratchet_step,
    symmetric_ratchet_step,
    MAX_SKIP,
    encrypt,
    decrypt,
)
from styx.crypto.keys import ecdh
from styx.crypto.aead import StyxDecryptionError as _AeadDecryptionError
from styx.transport import (
    StyxConfig,
    StyxListener,
    StyxMessage,
    build_memos,
    make_envelope,
    submit_styx_tx,
    CredentialPolicy,
    require_credential,
    PROTOCOL_VERSION,
)
from styx.session.state import (
    SessionState,
    save,
    load,
    list_sessions,
    state_path,
    _session_id,
)
from styx.session.disclosure import (
    save_root_history,
    load_root_history,
)
from styx.exceptions import (
    StyxHandshakeError,
    StyxDecryptionError,
    StyxSessionError,
    StyxCredentialError,
    StyxSubmitError,
    StyxDisclosureError,
)


class StyxSession:
    """
    Core session manager. Handles key storage, handshake, send, receive,
    and selective disclosure for a single XRPL wallet.
    """

    def __init__(
        self,
        wallet,
        client,
        config: StyxConfig,
        credential_policy: Optional[CredentialPolicy] = None,
        _listener=None,
        _spk_registry: Optional[Dict[str, bytes]] = None,
    ) -> None:
        self._wallet = wallet
        self._client = client
        self._config = config
        self._policy = credential_policy
        self._spk_registry = _spk_registry or {}

        self._wallet_addr: str = wallet.classic_address

        # Key storage directory
        self._keys_dir = Path(config.state_dir).expanduser() / "keys" / self._wallet_addr
        self._keys_dir.mkdir(parents=True, exist_ok=True)

        # Session state directory
        self._sessions_dir = Path(config.state_dir).expanduser() / "sessions"
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

        # Load or create identity key
        self._ik = self._load_or_create_ik()

        # Load or create signed prekey
        self._spk, self._spk_sig, self._spk_created_at = self._load_or_create_spk()

        # Listener for incoming messages
        self._listener = _listener or StyxListener(self._wallet_addr, client, config)

        # Generation tracking (in-memory)
        self._generation: Dict[str, int] = {}

        # Root key history (in-memory cache, backed by disk)
        self._root_history: Dict[str, Dict[int, bytes]] = {}

    # -----------------------------------------------------------------------
    # Key storage
    # -----------------------------------------------------------------------

    def _ik_path(self) -> Path:
        return self._keys_dir / "ik.json"

    def _spk_path(self) -> Path:
        return self._keys_dir / "spk.json"

    def _load_or_create_ik(self) -> StyxKeyPair:
        p = self._ik_path()
        if p.exists():
            d = json.loads(p.read_text())
            return StyxKeyPair(
                bytes.fromhex(d["private_hex"]),
                bytes.fromhex(d["public_hex"]),
            )
        kp = generate_identity_key()
        d = {
            "private_hex": kp.private.hex(),
            "public_hex": kp.public.hex(),
            "created_at": time.time(),
        }
        p.write_text(json.dumps(d, indent=2))
        p.chmod(0o600)
        return kp

    def _load_or_create_spk(self):
        """Returns (StyxKeyPair, sig_bytes, created_at_float)."""
        p = self._spk_path()
        if p.exists():
            d = json.loads(p.read_text())
            kp = StyxKeyPair(
                bytes.fromhex(d["private_hex"]),
                bytes.fromhex(d["public_hex"]),
            )
            sig = bytes.fromhex(d["sig_hex"])
            created_at = d.get("created_at", time.time())
            return kp, sig, created_at
        kp = generate_signed_prekey()
        sig = sign_spk(self._ik.private, kp.public, self._wallet_addr)
        created_at = time.time()
        self._save_spk(kp, sig, created_at)
        return kp, sig, created_at

    def _save_spk(self, kp: StyxKeyPair, sig: bytes, created_at: float) -> None:
        p = self._spk_path()
        d = {
            "private_hex": kp.private.hex(),
            "public_hex": kp.public.hex(),
            "sig_hex": sig.hex(),
            "created_at": created_at,
        }
        p.write_text(json.dumps(d, indent=2))
        p.chmod(0o600)

    # -----------------------------------------------------------------------
    # Root key history helpers
    # -----------------------------------------------------------------------

    def _record_root_key(self, session_id: str, generation: int, root_key: bytes) -> None:
        """Record a root key in memory and persist to disk."""
        if session_id not in self._root_history:
            self._root_history[session_id] = {}
        self._root_history[session_id][generation] = root_key
        save_root_history(self._sessions_dir, session_id, self._root_history[session_id])

    def _load_root_history_for(self, session_id: str) -> Dict[int, bytes]:
        """Load root history from disk if not already in memory."""
        if session_id not in self._root_history:
            raw = load_root_history(self._sessions_dir, session_id)
            self._root_history[session_id] = {
                int(k): bytes.fromhex(v) for k, v in raw.items()
            }
        return self._root_history[session_id]

    def get_root_key_at_generation(self, session_id: str, generation: int) -> bytes:
        """Return the root key recorded at a specific ratchet generation."""
        history = self._load_root_history_for(session_id)
        if generation not in history:
            raise StyxDisclosureError(
                f"Root key for session {session_id} generation {generation} not found"
            )
        return history[generation]

    # -----------------------------------------------------------------------
    # SPK fetch
    # -----------------------------------------------------------------------

    def _fetch_recipient_spk(self, recipient_addr: str) -> bytes:
        """Return the recipient's SPK public bytes."""
        if recipient_addr in self._spk_registry:
            return self._spk_registry[recipient_addr]
        # Poll the ledger for a PREKEY message from recipient_addr
        listener = StyxListener(recipient_addr, self._client, self._config)
        msgs = listener.poll(msg_type="PREKEY")
        if not msgs:
            raise StyxHandshakeError(
                f"No PREKEY found for {recipient_addr}. "
                "Recipient must publish a prekey first."
            )
        # Use the latest PREKEY
        latest = msgs[-1]
        spk_hex = latest.envelope.get("spk")
        if not spk_hex:
            raise StyxHandshakeError(f"PREKEY envelope missing 'spk' field for {recipient_addr}")
        return bytes.fromhex(spk_hex)

    # -----------------------------------------------------------------------
    # Handshake
    # -----------------------------------------------------------------------

    def handshake_initiate(self, recipient_addr: str) -> str:
        """
        Initiate an X3DH handshake with recipient_addr.
        Returns the session_id.
        """
        # Credential check
        if self._policy and self._policy.required:
            require_credential(self._wallet_addr, self._policy, self._client)

        # Fetch recipient SPK
        spk_recipient_pub = self._fetch_recipient_spk(recipient_addr)

        # Generate ephemeral key
        ek = generate_ephemeral_key()

        # X3DH Case A
        sk = x3dh_initiator(
            ik_sender=self._ik,
            ek_sender=ek,
            spk_recipient_pub=spk_recipient_pub,
            ik_recipient_pub=None,
            sender_addr=self._wallet_addr,
            recipient_addr=recipient_addr,
        )

        # Initiator ratchet initialization
        dhs = generate_ephemeral_key()
        shared_init = ecdh(dhs.private, spk_recipient_pub)
        rk, cks = kdf_rk(sk, shared_init)

        rs = RatchetState(
            root_key=rk,
            chain_key_send=cks,
            chain_key_recv=None,
            dh_send=dhs.private,
            dh_send_pub=dhs.public,
            dh_recv=spk_recipient_pub,
            n_send=0,
            n_recv=0,
            pn=0,
        )

        session_id = _session_id(self._wallet_addr, recipient_addr)

        # Record root key at generation 0
        self._generation[session_id] = 0
        self._record_root_key(session_id, 0, rk)

        # Build HS_INIT envelope
        envelope = make_envelope(
            "HS_INIT",
            sender=self._wallet_addr,
            recipient=recipient_addr,
            ik=self._ik.public.hex(),
            ek=ek.public.hex(),
            dh=dhs.public.hex(),
        )
        memos = build_memos(envelope)
        submit_styx_tx(self._wallet, self._client, memos, self._config)

        # Save state
        state = SessionState(
            session_id=session_id,
            sender_addr=self._wallet_addr,
            recipient_addr=recipient_addr,
            ratchet_state=rs,
            skipped_keys=SkippedKeyManager(),
            credential_policy=self._policy,
        )
        spath = state_path(self._sessions_dir, session_id)
        save(state, spath)

        return session_id

    def handshake_respond(self, handshake_msg: StyxMessage) -> str:
        """
        Respond to an HS_INIT message from initiator.
        Returns the session_id.
        """
        env = handshake_msg.envelope
        initiator_addr = env.get("s", handshake_msg.sender)
        ik_sender_pub = bytes.fromhex(env["ik"])
        ek_sender_pub = bytes.fromhex(env["ek"])
        dh_init = bytes.fromhex(env["dh"])

        # Credential check
        if self._policy and self._policy.required:
            require_credential(initiator_addr, self._policy, self._client)

        # X3DH responder
        sk = x3dh_responder(
            ik_responder=self._ik,
            spk_responder=self._spk,
            ik_sender_pub=ik_sender_pub,
            ek_sender_pub=ek_sender_pub,
            sender_addr=initiator_addr,
            recipient_addr=self._wallet_addr,
        )

        # Responder ratchet initialization
        shared_init = ecdh(self._spk.private, dh_init)
        rk, ckr = kdf_rk(sk, shared_init)

        rs = RatchetState(
            root_key=rk,
            chain_key_send=None,
            chain_key_recv=ckr,
            dh_send=self._spk.private,
            dh_send_pub=self._spk.public,
            dh_recv=dh_init,
            n_send=0,
            n_recv=0,
            pn=0,
        )

        session_id = _session_id(self._wallet_addr, initiator_addr)

        # Record root key at generation 0
        self._generation[session_id] = 0
        self._record_root_key(session_id, 0, rk)

        # Build HS_ACK envelope
        envelope = make_envelope(
            "HS_ACK",
            sender=self._wallet_addr,
            recipient=initiator_addr,
            spk=self._spk.public.hex(),
            sig=self._spk_sig.hex(),
            dh=self._spk.public.hex(),
        )
        memos = build_memos(envelope)
        submit_styx_tx(self._wallet, self._client, memos, self._config)

        # Save state
        state = SessionState(
            session_id=session_id,
            sender_addr=self._wallet_addr,
            recipient_addr=initiator_addr,
            ratchet_state=rs,
            skipped_keys=SkippedKeyManager(),
            credential_policy=self._policy,
        )
        spath = state_path(self._sessions_dir, session_id)
        save(state, spath)

        return session_id

    # -----------------------------------------------------------------------
    # Send / Receive
    # -----------------------------------------------------------------------

    def send(self, session_id: str, plaintext: str) -> str:
        """
        Encrypt and send a message. Returns tx_hash.
        """
        spath = state_path(self._sessions_dir, session_id)
        try:
            state = load(spath)
        except FileNotFoundError:
            raise StyxSessionError(f"Session not found: {session_id}")

        rs = state.ratchet_state

        # Partial DH ratchet if we have no send chain yet (responder first send)
        if rs.chain_key_send is None:
            new_dhs = generate_ephemeral_key()
            shared = ecdh(new_dhs.private, rs.dh_recv)
            new_rk, new_cks = kdf_rk(rs.root_key, shared)

            # Increment generation and record new root key
            gen = self._generation.get(session_id, 0) + 1
            self._generation[session_id] = gen
            self._record_root_key(session_id, gen, new_rk)

            rs = RatchetState(
                root_key=new_rk,
                chain_key_send=new_cks,
                chain_key_recv=rs.chain_key_recv,
                dh_send=new_dhs.private,
                dh_send_pub=new_dhs.public,
                dh_recv=rs.dh_recv,
                n_send=0,
                n_recv=rs.n_recv,
                pn=0,
            )

        # Symmetric ratchet step
        new_ck, mk = symmetric_ratchet_step(rs.chain_key_send)

        # Associated data
        recipient_addr = state.recipient_addr
        n = rs.n_send
        ad = self._wallet_addr.encode() + recipient_addr.encode() + n.to_bytes(8, "big")

        ct, nonce, tag = encrypt(mk, plaintext.encode("utf-8"), ad)

        current_gen = self._generation.get(session_id, 0)

        envelope = make_envelope(
            "DATA",
            sender=self._wallet_addr,
            recipient=recipient_addr,
            ct=ct.hex(),
            nc=nonce.hex(),
            tg=tag.hex(),
            dh=rs.dh_send_pub.hex(),
            n=n,
            g=current_gen,
            pn=rs.pn,
        )
        memos = build_memos(envelope)
        tx_hash = submit_styx_tx(self._wallet, self._client, memos, self._config)

        # Update ratchet state
        rs = RatchetState(
            root_key=rs.root_key,
            chain_key_send=new_ck,
            chain_key_recv=rs.chain_key_recv,
            dh_send=rs.dh_send,
            dh_send_pub=rs.dh_send_pub,
            dh_recv=rs.dh_recv,
            n_send=rs.n_send + 1,
            n_recv=rs.n_recv,
            pn=rs.pn,
        )

        state.ratchet_state = rs
        state.n_messages_sent += 1
        state.last_active = time.time()
        save(state, spath)

        return tx_hash

    def receive(self, session_id: str) -> List[dict]:
        """
        Receive and decrypt messages. Returns list of dicts with keys:
        plaintext, tx_hash, ledger_index, timestamp.
        """
        spath = state_path(self._sessions_dir, session_id)
        try:
            state = load(spath)
        except FileNotFoundError:
            raise StyxSessionError(f"Session not found: {session_id}")

        # Determine counterparty
        if state.sender_addr == self._wallet_addr:
            counterparty = state.recipient_addr
        else:
            counterparty = state.sender_addr

        msgs = self._listener.poll(from_address=counterparty, msg_type="DATA")

        results = []
        rs = state.ratchet_state
        skm = state.skipped_keys

        for msg in msgs:
            env = msg.envelope
            msg_dh_hex = env.get("dh", "")
            msg_n = env.get("n", 0)
            msg_pn = env.get("pn", 0)
            msg_g = env.get("g", 0)
            ct = bytes.fromhex(env.get("ct", ""))
            nonce = bytes.fromhex(env.get("nc", ""))
            tag = bytes.fromhex(env.get("tg", ""))

            msg_dh = bytes.fromhex(msg_dh_hex) if msg_dh_hex else None

            # Sender for AD construction: the counterparty sent this
            sender_addr = counterparty
            recipient_addr = self._wallet_addr
            ad = sender_addr.encode() + recipient_addr.encode() + msg_n.to_bytes(8, "big")

            plaintext_bytes = None

            # Check skipped keys first
            if msg_dh is not None:
                mk_skipped = skm.retrieve(msg_dh, msg_n)
                if mk_skipped is not None:
                    try:
                        plaintext_bytes = decrypt(mk_skipped, ct, nonce, tag, ad)
                    except _AeadDecryptionError as exc:
                        raise StyxDecryptionError("Decryption failed (skipped key)") from exc

            if plaintext_bytes is None:
                # Do we need a DH ratchet step?
                if msg_dh is not None and msg_dh != rs.dh_recv:
                    # Skip remaining messages in current receive chain (pn messages)
                    if rs.chain_key_recv is not None:
                        ck = rs.chain_key_recv
                        for skip_n in range(rs.n_recv, msg_pn):
                            ck, skip_mk = symmetric_ratchet_step(ck)
                            skm.store(rs.dh_recv, skip_n, skip_mk)

                    # DH ratchet step
                    rs = dh_ratchet_step(rs, msg_dh)

                    # Increment generation and record new root key
                    gen = self._generation.get(session_id, 0) + 1
                    self._generation[session_id] = gen
                    self._record_root_key(session_id, gen, rs.root_key)

                # Skip messages in new receive chain if out of order
                if rs.chain_key_recv is not None:
                    ck = rs.chain_key_recv
                    for skip_n in range(rs.n_recv, msg_n):
                        ck, skip_mk = symmetric_ratchet_step(ck)
                        if msg_dh is not None:
                            skm.store(msg_dh, skip_n, skip_mk)
                    rs = RatchetState(
                        root_key=rs.root_key,
                        chain_key_send=rs.chain_key_send,
                        chain_key_recv=ck,
                        dh_send=rs.dh_send,
                        dh_send_pub=rs.dh_send_pub,
                        dh_recv=rs.dh_recv,
                        n_send=rs.n_send,
                        n_recv=msg_n,
                        pn=rs.pn,
                    )

                # Decrypt
                new_ck, mk = symmetric_ratchet_step(rs.chain_key_recv)
                try:
                    plaintext_bytes = decrypt(mk, ct, nonce, tag, ad)
                except _AeadDecryptionError as exc:
                    raise StyxDecryptionError("Decryption failed") from exc

                rs = RatchetState(
                    root_key=rs.root_key,
                    chain_key_send=rs.chain_key_send,
                    chain_key_recv=new_ck,
                    dh_send=rs.dh_send,
                    dh_send_pub=rs.dh_send_pub,
                    dh_recv=rs.dh_recv,
                    n_send=rs.n_send,
                    n_recv=rs.n_recv + 1,
                    pn=rs.pn,
                )

            if plaintext_bytes is not None:
                results.append({
                    "plaintext": plaintext_bytes.decode("utf-8"),
                    "tx_hash": msg.tx_hash,
                    "ledger_index": msg.ledger_index,
                    "timestamp": msg.timestamp,
                })

        # Persist updated state
        state.ratchet_state = rs
        state.skipped_keys = skm
        state.n_messages_received += len(results)
        state.last_active = time.time()
        save(state, spath)

        return results

    # -----------------------------------------------------------------------
    # Status
    # -----------------------------------------------------------------------

    def status(self, session_id: str) -> dict:
        """Return session metadata."""
        spath = state_path(self._sessions_dir, session_id)
        try:
            state = load(spath)
        except FileNotFoundError:
            raise StyxSessionError(f"Session not found: {session_id}")

        return {
            "session_id": session_id,
            "n_messages_sent": state.n_messages_sent,
            "n_messages_received": state.n_messages_received,
            "last_active": state.last_active,
            "ratchet_generation": self._generation.get(session_id, 0),
            "agent_mode": state.agent_mode,
        }

    # -----------------------------------------------------------------------
    # Prekey publication
    # -----------------------------------------------------------------------

    def publish_prekey(self) -> str:
        """Publish this wallet's SPK as a PREKEY message to the ledger."""
        envelope = make_envelope(
            "PREKEY",
            sender=self._wallet_addr,
            recipient=self._wallet_addr,
            spk=self._spk.public.hex(),
            sig=self._spk_sig.hex(),
        )
        memos = build_memos(envelope)
        return submit_styx_tx(self._wallet, self._client, memos, self._config)

    def auto_rotate_spk(self, max_age_days: int = 60) -> Optional[str]:
        """
        Rotate SPK if older than max_age_days. Returns tx_hash if rotated, else None.
        """
        age_seconds = max_age_days * 86400
        if time.time() - self._spk_created_at < age_seconds:
            return None
        # Generate new SPK
        new_spk = generate_signed_prekey()
        new_sig = sign_spk(self._ik.private, new_spk.public, self._wallet_addr)
        new_created_at = time.time()
        self._save_spk(new_spk, new_sig, new_created_at)
        self._spk = new_spk
        self._spk_sig = new_sig
        self._spk_created_at = new_created_at
        return self.publish_prekey()
