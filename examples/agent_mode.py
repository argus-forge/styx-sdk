"""
agent_mode.py — Styx SDK: agent-to-agent structured payloads, auto-rotation,
                and selective disclosure key export.

TESTNET ONLY. Never modify network="mainnet" in this example.

AgentSession differences vs StyxClient:
  - All payloads are structured JSON (send_structured / receive_structured)
  - SPK auto-rotates on every send (30-day window)
  - No interactive prompts — safe to run inside automated pipelines
  - Selective disclosure: export per-generation keys for compliance audits

Prerequisites:
  - pip install -e ..  (from sdk/ directory)
  - Two funded XRPL testnet accounts
"""

import os

from styx.client import StyxAgentClient

# ---------------------------------------------------------------------------
# Step 1: Initialize two agents from environment-sourced seeds.
#         Seeds MUST come from env vars or a secrets vault — never hardcoded.
# ---------------------------------------------------------------------------
AGENT_A_SEED = os.environ.get("AGENT_A_SEED", "")
AGENT_B_SEED = os.environ.get("AGENT_B_SEED", "")
AGENT_B_ADDR = os.environ.get("AGENT_B_ADDR", "")  # Agent B's XRPL rAddress

if not all([AGENT_A_SEED, AGENT_B_SEED, AGENT_B_ADDR]):
    raise EnvironmentError(
        "Set AGENT_A_SEED, AGENT_B_SEED, and AGENT_B_ADDR environment variables before running."
    )

# Both agents default to network="testnet"
agent_a = StyxAgentClient(seed=AGENT_A_SEED, network="testnet")
agent_b = StyxAgentClient(seed=AGENT_B_SEED, network="testnet")

# ---------------------------------------------------------------------------
# Step 2: Agent B publishes a prekey bundle to XRPL (one-time setup).
# ---------------------------------------------------------------------------
print("Agent B: publishing prekey bundle...")
prekey_tx = agent_b.publish_prekey()
print(f"Agent B: prekey published — tx: {prekey_tx}")

# ---------------------------------------------------------------------------
# Step 3: Agent A initiates session with Agent B.
#         AgentSession marks the session as agent_mode=True in state.
# ---------------------------------------------------------------------------
print("\nAgent A: initiating session with Agent B...")
session_id = agent_a.handshake(AGENT_B_ADDR)
print(f"Agent A: session established — id: {session_id}")

# ---------------------------------------------------------------------------
# Step 4: Agent A sends a structured JSON payload.
#         send_structured() serializes to compact JSON, auto-rotates SPK,
#         then encrypts and submits to XRPL testnet.
# ---------------------------------------------------------------------------
print("\nAgent A: sending structured payload...")
tx1 = agent_a.send_structured(session_id, {
    "command": "status_request",
    "graph_id": "sentinel",
    "filters": {"min_ies": 20.0, "limit": 10},
    "request_id": "req-001",
})
print(f"Agent A: payload sent — tx: {tx1}")

# ---------------------------------------------------------------------------
# Step 5: Agent A sends a second payload (SPK auto-rotates again).
# ---------------------------------------------------------------------------
print("\nAgent A: sending second payload...")
tx2 = agent_a.send_structured(session_id, {
    "command": "influence_loop_query",
    "company": "Lockheed Martin",
    "request_id": "req-002",
})
print(f"Agent A: second payload sent — tx: {tx2}")

# ---------------------------------------------------------------------------
# Step 6: Agent B receives and parses structured payloads.
#         receive_structured() decrypts, JSON-parses, and returns a list of
#         dicts: {"payload": dict, "tx_hash": str, "ledger_index": int}
# ---------------------------------------------------------------------------
print("\nAgent B: receiving structured payloads...")
responses = agent_b.receive_structured(session_id)
for resp in responses:
    print(f"  payload: {resp['payload']}")
    print(f"  tx_hash: {resp['tx_hash']}")

# ---------------------------------------------------------------------------
# Step 7: Agent B replies with results.
# ---------------------------------------------------------------------------
print("\nAgent B: sending results...")
tx3 = agent_b.send_structured(session_id, {
    "status": "ok",
    "request_id": "req-001",
    "results": [
        {"legislator": "Calvert, Ken", "ies": 55.5},
        {"legislator": "Young, Don",  "ies": 48.3},
    ],
})
print(f"Agent B: results sent — tx: {tx3}")

replies = agent_a.receive_structured(session_id)
for r in replies:
    print(f"Agent A received results: {r['payload']}")

# ---------------------------------------------------------------------------
# Step 8: Selective disclosure — export generation keys for an auditor.
#         Disclosure keys are one-way and generation-scoped.
#         They do NOT expose identity keys, SPK private keys, or full state.
# ---------------------------------------------------------------------------
print("\nAgent A: exporting disclosure keys for generations 0 and 1...")
agent_a.export_disclosure(
    session_id,
    generations=[0, 1],
    output_path="./audit_keys.json",
)
print("Agent A: disclosure keys written to ./audit_keys.json (mode 0o600)")

# ---------------------------------------------------------------------------
# Step 9: List active sessions.
# ---------------------------------------------------------------------------
sessions = agent_a.list_sessions()
print(f"\nAgent A active sessions: {sessions}")

print("\nDone. Agent session complete — TESTNET only.")
