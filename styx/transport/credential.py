"""
XLS-70 Credential verification for Styx credentialed handshakes.

A CredentialPolicy specifies whether credentials are required and, if so,
what credential type and issuer are accepted. During handshake, both parties
must present a valid on-ledger XLS-70 credential if policy.required is True.
"""
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import AccountObjects
    XRPL_AVAILABLE = True
except ImportError:
    XRPL_AVAILABLE = False


class StyxCredentialError(Exception):
    """Raised when credential verification fails."""


@dataclass
class CredentialPolicy:
    """Defines the credential requirements for a Styx session."""
    required: bool = False
    credential_type: Optional[str] = None   # e.g. "KYC_VERIFIED"
    issuer: Optional[str] = None            # XRPL address of trusted issuer


def verify_credential(
    subject_address: str,
    policy: CredentialPolicy,
    client: Any,
) -> bool:
    """
    Verify that subject_address holds a valid XLS-70 credential matching policy.

    Args:
        subject_address: XRPL address to check.
        policy:          CredentialPolicy with type and issuer requirements.
        client:          xrpl JsonRpcClient.

    Returns True if credential is found and valid.
    Raises StyxCredentialError if required and not found.
    """
    if not policy.required:
        return True

    if not XRPL_AVAILABLE:
        raise StyxCredentialError("xrpl-py required for credential verification")

    request = AccountObjects(
        account=subject_address,
        type="credential",
    )
    try:
        response = client.request(request)
    except Exception as exc:
        raise StyxCredentialError(
            f"Failed to fetch credentials for {subject_address}: {exc}"
        ) from exc

    objects = response.result.get("account_objects", [])
    for obj in objects:
        if obj.get("LedgerEntryType") != "Credential":
            continue
        cred_type_hex = obj.get("CredentialType", "")
        try:
            cred_type = bytes.fromhex(cred_type_hex).decode("utf-8", errors="replace")
        except Exception:
            cred_type = cred_type_hex

        issuer = obj.get("Issuer", "")
        accepted = bool(obj.get("Flags", 0) & 0x00010000)  # lsfAccepted flag

        if not accepted:
            continue

        type_match = (policy.credential_type is None or cred_type == policy.credential_type)
        issuer_match = (policy.issuer is None or issuer == policy.issuer)

        if type_match and issuer_match:
            return True

    raise StyxCredentialError(
        f"No valid credential found for {subject_address} "
        f"(type={policy.credential_type!r}, issuer={policy.issuer!r})"
    )


def require_credential(
    subject_address: str,
    policy: CredentialPolicy,
    client: Any,
) -> None:
    """
    Enforce credential policy. Raises StyxCredentialError if policy not met.
    No-op if policy.required is False.
    """
    verify_credential(subject_address, policy, client)


def credential_to_dict(policy: CredentialPolicy) -> Optional[dict]:
    """Serialize CredentialPolicy to dict for memo inclusion."""
    if not policy.required:
        return None
    return {
        "required": policy.required,
        "type": policy.credential_type,
        "issuer": policy.issuer,
    }


def credential_from_dict(d: Optional[dict]) -> CredentialPolicy:
    """Deserialize CredentialPolicy from memo dict."""
    if d is None:
        return CredentialPolicy(required=False)
    return CredentialPolicy(
        required=d.get("required", False),
        credential_type=d.get("type"),
        issuer=d.get("issuer"),
    )
