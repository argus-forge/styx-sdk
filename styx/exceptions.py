"""
Styx exception hierarchy.

All exceptions inherit from StyxError so callers can catch the base class.
"""


class StyxError(Exception):
    """Base class for all Styx SDK exceptions."""


class StyxHandshakeError(StyxError):
    """Raised when X3DH handshake initiation or completion fails."""


class StyxDecryptionError(StyxError):
    """Raised when AES-GCM authentication or decryption fails."""


class StyxSessionError(StyxError):
    """Raised on session state load/save/lookup failures."""


class StyxCredentialError(StyxError):
    """Raised when XLS-70 credential verification fails."""


class StyxMemoError(StyxError):
    """Raised when XRPL memo construction or parsing fails."""


class StyxSubmitError(StyxError):
    """Raised when XRPL transaction submission fails."""


class StyxPayloadTooLarge(StyxError):
    """Raised when plaintext payload exceeds the maximum allowed size (2700 bytes)."""


class StyxDisclosureError(StyxError):
    """Raised when selective disclosure key derivation or decryption fails."""


class StyxAgentError(StyxError):
    """Raised on agent-mode specific failures (e.g. non-JSON payload in structured send)."""
