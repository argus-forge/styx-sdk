"""
Styx memo construction and parsing.

Message envelope (JSON, UTF-8 encoded, then hex) stored in AccountSet MemoData.
Chunked messages use MemoFormat to carry chunk index / total.

Memo wire format (per chunk):
  MemoType:   hex("Styx\x00")
  MemoFormat: hex("{chunk_index}/{total_chunks}")   -- omitted for single memos
  MemoData:   hex(JSON envelope bytes)

JSON envelope fields:
  v:    protocol version string
  t:    message type ("HS_INIT" | "HS_ACK" | "DATA" | "REKEY" | "PREKEY")
  s:    sender XRPL address
  r:    recipient XRPL address
  n:    message number (int, for DATA messages)
  g:    ratchet generation (int, for DATA messages)
  dh:   DH ratchet public key hex (for DATA/HS messages)
  ct:   ciphertext hex
  nc:   nonce hex (12 bytes)
  tg:   tag hex (16 bytes)
  ik:   identity public key hex (for HS_INIT)
  ek:   ephemeral public key hex (for HS_INIT)
  spk:  signed prekey public key hex (for HS_ACK / PREKEY)
  sig:  SPK signature hex (for HS_ACK / PREKEY)
  pn:   previous chain length (int, for DATA)
  cred: credential object (optional, for credentialed handshakes)
"""
import json
from typing import Any, Dict, List, Optional, Tuple


MEMO_TYPE_HEX = bytes("Styx\x00", "utf-8").hex().upper()
PROTOCOL_VERSION = "1.2.0"


class StyxMemoError(Exception):
    """Raised when memo parsing fails."""


class StyxPayloadTooLarge(Exception):
    """Raised when plaintext payload exceeds the maximum allowed size."""


def _to_hex(data: bytes) -> str:
    return data.hex().upper()


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def encode_memo(envelope: Dict[str, Any]) -> str:
    """Serialize envelope dict to hex-encoded JSON bytes."""
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    return _to_hex(raw)


def decode_memo(memo_data_hex: str) -> Dict[str, Any]:
    """Deserialize hex-encoded JSON bytes to envelope dict."""
    try:
        raw = _from_hex(memo_data_hex)
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise StyxMemoError(f"Failed to decode memo: {exc}") from exc


def build_memos(envelope: Dict[str, Any], chunk_size: int = 900, max_chunks: int = 3) -> List[Dict]:
    """
    Build one or more XRPL memo dicts from envelope.

    If the serialized envelope exceeds chunk_size bytes, it is split across
    multiple memos (up to max_chunks). Each chunk memo carries a MemoFormat
    of hex("{i}/{total}").

    Returns list of {"MemoType": ..., "MemoData": ..., "MemoFormat": ...} dicts
    ready to embed in an AccountSet Memos field.

    Raises StyxPayloadTooLarge if total payload exceeds max_chunks * chunk_size.
    """
    raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    total_bytes = len(raw)
    max_payload = chunk_size * max_chunks

    if total_bytes > max_payload:
        raise StyxPayloadTooLarge(
            f"Payload {total_bytes} bytes exceeds max {max_payload} bytes "
            f"({max_chunks} chunks × {chunk_size} bytes)"
        )

    if total_bytes <= chunk_size:
        memo = {
            "Memo": {
                "MemoType": MEMO_TYPE_HEX,
                "MemoData": _to_hex(raw),
            }
        }
        return [memo]

    # Chunk the raw bytes
    chunks = [raw[i:i + chunk_size] for i in range(0, total_bytes, chunk_size)]
    total = len(chunks)
    memos = []
    for i, chunk in enumerate(chunks):
        fmt = f"{i}/{total}".encode("utf-8")
        memos.append({
            "Memo": {
                "MemoType": MEMO_TYPE_HEX,
                "MemoFormat": _to_hex(fmt),
                "MemoData": _to_hex(chunk),
            }
        })
    return memos


def parse_memos(memos: List[Dict]) -> Optional[Dict[str, Any]]:
    """
    Parse a list of XRPL Memo dicts into a single Styx envelope.

    Returns None if no Styx memos found. Reassembles chunked memos.
    Raises StyxMemoError on parse failure.
    """
    styx_memos = []
    for entry in memos:
        memo = entry.get("Memo", entry)
        mtype = memo.get("MemoType", "")
        if mtype.upper() != MEMO_TYPE_HEX:
            continue
        styx_memos.append(memo)

    if not styx_memos:
        return None

    if len(styx_memos) == 1 and "MemoFormat" not in styx_memos[0]:
        # Single, unchunked memo
        return decode_memo(styx_memos[0]["MemoData"])

    # Chunked — reassemble by MemoFormat "{i}/{total}"
    indexed: List[Tuple[int, bytes]] = []
    for memo in styx_memos:
        fmt_hex = memo.get("MemoFormat", "")
        try:
            fmt_str = _from_hex(fmt_hex).decode("utf-8")
            idx, _ = fmt_str.split("/")
            chunk_bytes = _from_hex(memo["MemoData"])
            indexed.append((int(idx), chunk_bytes))
        except Exception as exc:
            raise StyxMemoError(f"Bad chunk format: {exc}") from exc

    indexed.sort(key=lambda x: x[0])
    raw = b"".join(chunk for _, chunk in indexed)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise StyxMemoError(f"Failed to decode reassembled chunk: {exc}") from exc


def make_envelope(
    msg_type: str,
    sender: str,
    recipient: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Helper to build a typed envelope dict."""
    env: Dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "t": msg_type,
        "s": sender,
        "r": recipient,
    }
    env.update({k: v for k, v in kwargs.items() if v is not None})
    return env
