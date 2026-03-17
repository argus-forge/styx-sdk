"""
basic_usage.py — Styx SDK: two-party handshake, send, and receive.

TESTNET ONLY. Never modify network="mainnet" in this example.

This example simulates two agents communicating end-to-end:
  - Alice initiates an encrypted session with Bob over XRPL testnet
  - Alice sends a message; Bob receives and decrypts it
  - Reply flow: Bob sends back; Alice receives

Prerequisites:
  - pip install -e ..  (from sdk/ directory)
  - Two funded XRPL testnet accounts (get test XRP at https://xrpl.org/xrp-testnet-faucet.html)
"""

from styx.client import StyxClient

# ---------------------------------------------------------------------------
# Step 1: Initialize both parties with their XRPL testnet seeds.
#         Seeds are loaded from environment in production — never hardcoded.
# ---------------------------------------------------------------------------
import os

ALICE_SEED = os.environ.get("ALICE_SEED", "")
BOB_SEED   = os.environ.get("BOB_SEED", "")
BOB_ADDR   = os.environ.get("BOB_ADDR", "")   # Bob's XRPL rAddress

if not all([ALICE_SEED, BOB_SEED, BOB_ADDR]):
    raise EnvironmentError(
        "Set ALICE_SEED, BOB_SEED, and BOB_ADDR environment variables before running."
    )

# Both clients default to network="testnet"
alice = StyxClient(seed=ALICE_SEED, network="testnet")
bob   = StyxClient(seed=BOB_SEED,   network="testnet")

# ---------------------------------------------------------------------------
# Step 2: Bob publishes a prekey bundle to XRPL.
#         This is a one-time setup. Bob's signed prekey is stored on-ledger
#         so Alice can initiate a session without Bob being online.
# ---------------------------------------------------------------------------
print("Bob: publishing prekey bundle to XRPL testnet...")
prekey_tx = bob.publish_prekey()
print(f"Bob: prekey published — tx: {prekey_tx}")

# ---------------------------------------------------------------------------
# Step 3: Alice performs X3DH key agreement and initiates a session.
#         The handshake_initiate call fetches Bob's prekey from XRPL,
#         derives a shared secret via Modified X3DH, and bootstraps the
#         Double Ratchet. A session ID is returned for subsequent calls.
# ---------------------------------------------------------------------------
print("\nAlice: initiating encrypted session with Bob...")
session_id = alice.handshake(BOB_ADDR)
print(f"Alice: session established — id: {session_id}")

# ---------------------------------------------------------------------------
# Step 4: Alice encrypts and sends a message.
#         The plaintext is encrypted with AES-256-GCM, serialized as an
#         XRPL AccountSet memo, and submitted to testnet. The Double Ratchet
#         advances on every send.
# ---------------------------------------------------------------------------
print("\nAlice: sending encrypted message...")
tx_hash = alice.send(session_id, "Hello Bob — this message is encrypted on XRPL testnet.")
print(f"Alice: message sent — tx: {tx_hash}")

# ---------------------------------------------------------------------------
# Step 5: Bob polls for new messages and decrypts.
#         receive() fetches AccountSet memos from XRPL, reassembles any
#         chunks, and decrypts each message using the shared Double Ratchet
#         state. Returns a list of dicts with plaintext and metadata.
# ---------------------------------------------------------------------------
print("\nBob: receiving messages...")
messages = bob.receive(session_id)
for msg in messages:
    print(f"Bob received: {msg['plaintext']}")

# ---------------------------------------------------------------------------
# Step 6: Bob replies. The ratchet advances in the reverse direction.
# ---------------------------------------------------------------------------
print("\nBob: sending reply...")
reply_hash = bob.send(session_id, "Got it, Alice. Session secure.")
print(f"Bob: reply sent — tx: {reply_hash}")

print("\nAlice: receiving reply...")
replies = alice.receive(session_id)
for msg in replies:
    print(f"Alice received: {msg['plaintext']}")

# ---------------------------------------------------------------------------
# Step 7: Inspect session status (ratchet generation, message count).
# ---------------------------------------------------------------------------
status = alice.status(session_id)
print(f"\nAlice session status: {status}")

print("\nDone. All messages encrypted end-to-end over XRPL testnet.")
