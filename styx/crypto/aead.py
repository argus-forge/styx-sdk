"""
Styx AEAD — AES-256-GCM encrypt/decrypt via pycryptodome.
96-bit random nonce, 16-byte auth tag.
"""
import os

from Crypto.Cipher import AES


class StyxDecryptionError(Exception):
    """Raised when AES-GCM authentication fails."""


def encrypt(message_key: bytes, plaintext: bytes, associated_data: bytes) -> tuple:
    """
    Encrypt plaintext with AES-256-GCM.

    Returns (ciphertext, nonce, tag).
    nonce: 12 random bytes (96-bit).
    tag: 16 bytes.
    """
    nonce = os.urandom(12)
    cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag


def decrypt(
    message_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: bytes,
) -> bytes:
    """
    Decrypt and authenticate ciphertext.

    Raises StyxDecryptionError if authentication fails.
    """
    cipher = AES.new(message_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except (ValueError, KeyError) as exc:
        raise StyxDecryptionError("AES-GCM authentication failed") from exc
