# Styx SDK — End-to-End Encrypted Communication over XRPL

Python SDK implementing the Styx Protocol (Modified X3DH + Double Ratchet over XRPL AccountSet memos)

**Patent Pending — Sentinel Intelligence LLC.**
**TESTNET by default. Mainnet requires explicit configuration.**

---

## Install

```bash
pip install -e .
```

**Requirements:** Python >= 3.10, xrpl-py, cryptography, pynacl

---

## Quickstart

```python
from styx.client import StyxClient

# Both parties initialize with their XRPL testnet seeds
alice = StyxClient(seed="sEdAliceSeedHere", network="testnet")
bob   = StyxClient(seed="sEdBobSeedHere",   network="testnet")

# Step 1: Bob publishes a prekey bundle to XRPL (one-time setup)
bob.publish_prekey()

# Step 2: Alice initiates an encrypted session with Bob
session_id = alice.handshake("rBobXRPLAddress")

# Step 3: Alice sends an encrypted message (written as XRPL AccountSet memo)
tx_hash = alice.send(session_id, "Hello, Bob — this message is encrypted on XRPL")

# Step 4: Bob receives and decrypts
messages = bob.receive(session_id)
for msg in messages:
    print(msg["plaintext"])  # "Hello, Bob — this message is encrypted on XRPL"
```

---

## Agent Mode

For AI agent-to-agent communication with structured JSON payloads:

```python
from styx.client import StyxAgentClient

agent_a = StyxAgentClient(seed="sEdAgentASeed", network="testnet")
agent_b = StyxAgentClient(seed="sEdAgentBSeed", network="testnet")

agent_b.publish_prekey()
session_id = agent_a.handshake("rAgentBAddress")

# Send structured payload
agent_a.send_structured(session_id, {
    "command": "status",
    "graph_id": "sentinel",
    "timestamp": 1710000000,
})

# Receive structured responses
responses = agent_b.receive_structured(session_id)
for resp in responses:
    print(resp)  # dict
```

---

## Credential-Gated Handshake

Restrict sessions to counterparties holding a specific XRPL credential:

```python
from styx.client import StyxClient

client = StyxClient(
    seed="sEdAliceSeed",
    network="testnet",
    credential_policy={
        "required": True,
        "type": "KYC_VERIFIED",
        "issuer": "rIssuerXRPLAddress",
    },
)
session_id = client.handshake("rRecipientAddress")
```

---

## Selective Disclosure (Compliance / Audit)

Export generation-specific decryption keys for auditors without exposing the full session:

```python
# Export keys for generations 0, 1, 2 only
client.export_disclosure(
    session_id,
    generations=[0, 1, 2],
    output_path="./audit_keys.json",
)
```

---

## Architecture

| Module | Description |
|--------|-------------|
| `styx.client` | `StyxClient` and `StyxAgentClient` — top-level public API |
| `styx.crypto` | X3DH key agreement, Double Ratchet, AES-GCM AEAD, KDF chains, skipped-key store |
| `styx.transport` | XRPL AccountSet memo encode/decode, chunking, credential policy, network config |
| `styx.session` | Session lifecycle (handshake, send, receive), agent mode, disclosure key derivation, state persistence |
| `styx.exceptions` | `StyxPayloadTooLarge`, `StyxDecryptionError`, `StyxCredentialError` |

---

## Testing

```bash
python3 -m pytest -v
```

Expected output: 44 tests, all passing.

---

## Examples

See the `examples/` directory:

- `examples/basic_usage.py` — Two-party key generation, handshake, send/receive
- `examples/agent_mode.py` — Agent-to-agent structured payloads, auto-rotation, selective disclosure

---

## License

MIT

---

## Patent Notice

Styx Protocol is patent pending (USPTO SENTINEL-STYX-PROV-001). This SDK is licensed under MIT for use, testing, and integration.
