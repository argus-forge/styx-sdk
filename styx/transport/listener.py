"""
StyxListener — polls account_tx to retrieve Styx messages for an address.

Reassembles chunked memos, filters by recipient, and tracks the last seen
ledger index to avoid re-processing old transactions.
"""
import time
from typing import Any, Dict, List, Optional

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import AccountTx
    XRPL_AVAILABLE = True
except ImportError:
    XRPL_AVAILABLE = False

from .config import StyxConfig
from .memo import parse_memos, MEMO_TYPE_HEX
from .tx import StyxMessage


class StyxListener:
    """
    Polls the XRPL for Styx messages sent to or from a given address.

    Maintains a ledger cursor so repeated calls only return new messages.
    """

    def __init__(self, address: str, client: Any, config: StyxConfig) -> None:
        self.address = address
        self.client = client
        self.config = config
        self._min_ledger: Optional[int] = None  # exclusive lower bound

    def poll(
        self,
        from_address: Optional[str] = None,
        msg_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[StyxMessage]:
        """
        Fetch new Styx messages for self.address.

        Args:
            from_address: If set, only return messages from this sender.
            msg_type:     If set, only return messages of this type.
            limit:        Max transactions to scan per poll.

        Returns list of StyxMessage objects, oldest first.
        """
        if not XRPL_AVAILABLE:
            return []

        request = AccountTx(
            account=self.address,
            limit=limit,
            ledger_index_min=self._min_ledger or -1,
            forward=True,
        )
        try:
            response = self.client.request(request)
        except Exception:
            return []

        txs = response.result.get("transactions", [])
        messages: List[StyxMessage] = []

        for entry in txs:
            tx = entry.get("tx", entry.get("tx_json", {}))
            meta = entry.get("meta", {})

            # Only AccountSet — never accept Payment
            if tx.get("TransactionType") != "AccountSet":
                continue

            # Must succeed on ledger
            if meta.get("TransactionResult") != "tesSUCCESS":
                continue

            memos_raw = tx.get("Memos", [])
            if not memos_raw:
                continue

            try:
                envelope = parse_memos(memos_raw)
            except Exception:
                continue

            if envelope is None:
                continue

            # Filter by recipient
            if envelope.get("r") != self.address:
                continue

            # Filter by sender
            sender = envelope.get("s", tx.get("Account", ""))
            if from_address and sender != from_address:
                continue

            # Filter by message type
            if msg_type and envelope.get("t") != msg_type:
                continue

            ledger_index: int = entry.get("ledger_index", 0)
            tx_hash: str = tx.get("hash", "")

            # ripple epoch: 2000-01-01T00:00:00 UTC = unix 946684800
            ripple_close = entry.get("close_time_iso", None)
            if ripple_close:
                import datetime
                ts = datetime.datetime.fromisoformat(
                    ripple_close.replace("Z", "+00:00")
                ).timestamp()
            else:
                close_time = entry.get("close_time", 0)
                ts = close_time + 946684800 if close_time else time.time()

            messages.append(StyxMessage(
                envelope=envelope,
                tx_hash=tx_hash,
                ledger_index=ledger_index,
                timestamp=ts,
                sender=sender,
            ))

            # Advance cursor
            if self._min_ledger is None or ledger_index >= self._min_ledger:
                self._min_ledger = ledger_index + 1

        return messages

    def reset_cursor(self) -> None:
        """Reset the ledger cursor to re-scan from the beginning."""
        self._min_ledger = None
