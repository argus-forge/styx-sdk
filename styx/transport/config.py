"""
Styx transport configuration — network endpoints and StyxConfig dataclass.
"""
from dataclasses import dataclass, field

TESTNET_URL = "https://s.altnet.rippletest.net:51234"
MAINNET_URL = "https://xrplcluster.com"

NETWORK_URLS = {
    "testnet": TESTNET_URL,
    "mainnet": MAINNET_URL,
}


@dataclass
class StyxConfig:
    """Network configuration for the Styx transport layer."""
    network: str = "testnet"
    max_retries: int = 3
    retry_delay: float = 1.0
    chunk_size: int = 900        # bytes; messages > this get chunked
    max_chunks: int = 3          # max memos per AccountSet tx
    max_payload: int = 2700      # bytes; raises StyxPayloadTooLarge above this
    memo_type: str = "5374797800"  # hex("Styx\x00")
    state_dir: str = "~/.styx"

    @property
    def url(self) -> str:
        if self.network not in NETWORK_URLS:
            raise ValueError(f"Unknown network: {self.network!r}. Use 'testnet' or 'mainnet'.")
        return NETWORK_URLS[self.network]
