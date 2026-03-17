"""
STYX-SDK-02: Transport layer unit tests.

All tests are offline (no XRPL connection required).
"""
import json
import pytest

from styx.transport.config import StyxConfig, TESTNET_URL, MAINNET_URL
from styx.transport.memo import (
    build_memos,
    parse_memos,
    make_envelope,
    encode_memo,
    decode_memo,
    StyxMemoError,
    StyxPayloadTooLarge,
    MEMO_TYPE_HEX,
)
from styx.transport.credential import CredentialPolicy, StyxCredentialError


# ---------------------------------------------------------------------------
# Test 1: Config defaults
# ---------------------------------------------------------------------------
class TestConfig:
    def test_default_network_is_testnet(self):
        cfg = StyxConfig()
        assert cfg.network == "testnet"
        assert cfg.url == TESTNET_URL

    def test_mainnet_config(self):
        cfg = StyxConfig(network="mainnet")
        assert cfg.url == MAINNET_URL

    def test_unknown_network_raises(self):
        cfg = StyxConfig(network="badnet")
        with pytest.raises(ValueError, match="Unknown network"):
            _ = cfg.url


# ---------------------------------------------------------------------------
# Test 2: Memo encode/decode roundtrip
# ---------------------------------------------------------------------------
class TestMemoEncodeDecode:
    def test_roundtrip(self):
        env = {"v": "1.2.0", "t": "DATA", "s": "rAlice", "r": "rBob", "n": 0}
        hex_str = encode_memo(env)
        decoded = decode_memo(hex_str)
        assert decoded == env

    def test_decode_bad_hex_raises(self):
        with pytest.raises(StyxMemoError):
            decode_memo("ZZZZ")


# ---------------------------------------------------------------------------
# Test 3: Single memo build/parse
# ---------------------------------------------------------------------------
class TestSingleMemo:
    def test_small_payload_one_memo(self):
        env = make_envelope("DATA", "rAlice", "rBob", ct="deadbeef", nc="aabbcc", tg="ff00")
        memos = build_memos(env, chunk_size=900)
        assert len(memos) == 1
        assert "MemoFormat" not in memos[0]["Memo"]
        assert memos[0]["Memo"]["MemoType"] == MEMO_TYPE_HEX

    def test_parse_single_memo(self):
        env = make_envelope("DATA", "rAlice", "rBob", ct="deadbeef")
        memos = build_memos(env, chunk_size=900)
        result = parse_memos(memos)
        assert result["t"] == "DATA"
        assert result["s"] == "rAlice"
        assert result["r"] == "rBob"


# ---------------------------------------------------------------------------
# Test 4: Chunked memo build/parse
# ---------------------------------------------------------------------------
class TestChunkedMemo:
    def test_large_payload_chunks(self):
        # Create a payload that exceeds chunk_size=50
        env = make_envelope("DATA", "rAlice", "rBob", ct="A" * 200)
        memos = build_memos(env, chunk_size=50, max_chunks=10)
        assert len(memos) > 1
        # Each chunk memo has a MemoFormat
        for m in memos:
            assert "MemoFormat" in m["Memo"]

    def test_chunked_reassembly(self):
        env = make_envelope("DATA", "rAlice", "rBob", ct="B" * 300, n=5)
        memos = build_memos(env, chunk_size=50, max_chunks=20)
        result = parse_memos(memos)
        assert result["n"] == 5
        assert result["ct"] == "B" * 300


# ---------------------------------------------------------------------------
# Test 5: Payload too large
# ---------------------------------------------------------------------------
class TestPayloadTooLarge:
    def test_raises_when_exceeds_max(self):
        env = make_envelope("DATA", "rAlice", "rBob", ct="X" * 3000)
        with pytest.raises(StyxPayloadTooLarge):
            build_memos(env, chunk_size=900, max_chunks=3)


# ---------------------------------------------------------------------------
# Test 6: parse_memos returns None for non-Styx memos
# ---------------------------------------------------------------------------
class TestNonStyxMemos:
    def test_wrong_memo_type_returns_none(self):
        memos = [{"Memo": {"MemoType": "4f74686572", "MemoData": "deadbeef"}}]
        result = parse_memos(memos)
        assert result is None

    def test_empty_list_returns_none(self):
        assert parse_memos([]) is None


# ---------------------------------------------------------------------------
# Test 7: CredentialPolicy — no-op when not required
# ---------------------------------------------------------------------------
class TestCredentialPolicy:
    def test_not_required_returns_true(self):
        from styx.transport.credential import verify_credential
        policy = CredentialPolicy(required=False)
        # No client needed when not required
        assert verify_credential("rAnyone", policy, None) is True

    def test_required_no_xrpl_raises(self):
        """When xrpl-py unavailable, required policy raises StyxCredentialError."""
        import styx.transport.credential as cmod
        orig = cmod.XRPL_AVAILABLE
        cmod.XRPL_AVAILABLE = False
        try:
            policy = CredentialPolicy(required=True, credential_type="KYC_VERIFIED")
            with pytest.raises(StyxCredentialError, match="xrpl-py required"):
                cmod.verify_credential("rSubject", policy, None)
        finally:
            cmod.XRPL_AVAILABLE = orig


# ---------------------------------------------------------------------------
# Test 8: No Payment in transport module source
# ---------------------------------------------------------------------------
class TestNoPaymentTransaction:
    def test_payment_not_in_tx_module(self):
        import styx.transport.tx as tx_mod
        import inspect
        source = inspect.getsource(tx_mod)
        # "Payment" must not appear as a transaction type literal
        assert "TransactionType.*Payment" not in source
        assert '"Payment"' not in source
        assert "'Payment'" not in source
