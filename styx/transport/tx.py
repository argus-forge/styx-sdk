"""
Styx XRPL transaction builder and submitter.

Only AccountSet transactions are used. Payment transactions are
a constitutional violation and must never appear in this module.
"""
import time
from typing import Any, Dict, List, Optional

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.transactions import AccountSet
    from xrpl.wallet import Wallet
    from xrpl.transaction import submit_and_wait
    XRPL_AVAILABLE = True
except ImportError:
    XRPL_AVAILABLE = False

from .config import StyxConfig


class StyxSubmitError(Exception):
    """Raised when XRPL transaction submission fails."""


class StyxMessage:
    """A parsed Styx message retrieved from the ledger."""

    def __init__(
        self,
        envelope: Dict[str, Any],
        tx_hash: str,
        ledger_index: int,
        timestamp: float,
        sender: str,
    ) -> None:
        self.envelope = envelope
        self.tx_hash = tx_hash
        self.ledger_index = ledger_index
        self.timestamp = timestamp
        self.sender = sender

    @property
    def msg_type(self) -> str:
        return self.envelope.get("t", "")

    @property
    def recipient(self) -> str:
        return self.envelope.get("r", "")


def build_accountset(
    sender_address: str,
    memos: List[Dict],
    sequence: Optional[int] = None,
    fee: str = "12",
) -> Dict[str, Any]:
    """
    Build an AccountSet transaction dict with Styx memos.

    Returns a plain dict compatible with xrpl-py's AccountSet model.
    """
    tx: Dict[str, Any] = {
        "TransactionType": "AccountSet",
        "Account": sender_address,
        "Memos": memos,
        "Fee": fee,
    }
    if sequence is not None:
        tx["Sequence"] = sequence
    return tx


def submit_styx_tx(
    wallet: Any,
    client: Any,
    memos: List[Dict],
    config: StyxConfig,
) -> str:
    """
    Submit an AccountSet with Styx memos to the XRPL.

    Returns the transaction hash on success.
    Raises StyxSubmitError on failure.

    wallet: xrpl.wallet.Wallet
    client: xrpl.clients.JsonRpcClient
    """
    if not XRPL_AVAILABLE:
        raise StyxSubmitError("xrpl-py is not installed")

    for attempt in range(config.max_retries):
        try:
            tx = AccountSet(
                account=wallet.address,
                memos=memos,
            )
            response = submit_and_wait(tx, client, wallet)
            result = response.result
            if result.get("meta", {}).get("TransactionResult") == "tesSUCCESS":
                return result.get("hash", "")
            raise StyxSubmitError(
                f"Transaction failed: {result.get('meta', {}).get('TransactionResult')}"
            )
        except StyxSubmitError:
            raise
        except Exception as exc:
            if attempt < config.max_retries - 1:
                time.sleep(config.retry_delay)
                continue
            raise StyxSubmitError(f"Submit failed after {config.max_retries} attempts: {exc}") from exc

    raise StyxSubmitError("Submit failed: exhausted retries")
