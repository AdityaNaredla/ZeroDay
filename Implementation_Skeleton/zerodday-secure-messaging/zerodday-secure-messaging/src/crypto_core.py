"""
ZeroDay Secure Messaging — Crypto Core
Primitives: X25519, HKDF-SHA256, AES-256-GCM, Ed25519, SHA-256
"""
import os
import struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import json

# Protocol constants — NOT secrets, safe to be in code
PROTOCOL_SALT = hashlib.sha256(b"ZeroDay-v1-salt").digest()
SESSION_KEY_INFO = b"zeroday-session-key"
BASE_NONCE_INFO = b"zeroday-base-nonce"
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB
MAX_SEQ = 2**32 - 1


@dataclass
class SessionKeys:
    """Holds derived session material. Non-serializable by design."""
    key: bytes  # 32 bytes AES-256 key
    base_nonce: bytes  # 12 bytes GCM nonce base

    def __getstate__(self):
        raise RuntimeError("SessionKeys cannot be serialized — security policy")

    def __del__(self):
        # Zero key material on destruction
        if hasattr(self, 'key') and self.key:
            self.key = b'\x00' * len(self.key)
        if hasattr(self, 'base_nonce') and self.base_nonce:
            self.base_nonce = b'\x00' * len(self.base_nonce)


class IdentityKeyPair:
    """Long-term Ed25519 signing key pair."""

    def __init__(self):
        self._private = Ed25519PrivateKey.generate()
        self.public = self._private.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @staticmethod
    def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> bool:
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pk.verify(signature, data)
            return True
        except Exception:
            return False


class EphemeralKeyPair:
    """Per-session X25519 key pair. Never persisted."""

    def __init__(self):
        self._private = X25519PrivateKey.generate()
        self.public = self._private.public_key()

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def compute_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared = self._private.exchange(peer_pk)
        # Check for all-zero output (point at infinity)
        if shared == b'\x00' * 32:
            raise ValueError("ERR_KEY_EXCHANGE_FAIL: shared secret is zero")
        return shared

    def destroy(self):
        """Zero the private key from memory."""
        self._private = None


def derive_session_keys(shared_secret: bytes) -> SessionKeys:
    """HKDF-SHA256: derive AES key + base nonce from shared secret."""
    # Derive 32-byte session key
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=PROTOCOL_SALT,
        info=SESSION_KEY_INFO,
    ).derive(shared_secret)

    # Derive 12-byte base nonce
    base_nonce = HKDF(
        algorithm=hashes.SHA256(),
        length=12,
        salt=PROTOCOL_SALT,
        info=BASE_NONCE_INFO,
    ).derive(shared_secret)

    return SessionKeys(key=key, base_nonce=base_nonce)


def _build_nonce(base_nonce: bytes, seq: int) -> bytes:
    """Nonce = base_nonce XOR seq (padded to 12 bytes)."""
    seq_bytes = seq.to_bytes(12, byteorder='big')
    return bytes(a ^ b for a, b in zip(base_nonce, seq_bytes))


def encrypt_message(session: SessionKeys, seq: int, plaintext: bytes, header: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt with AAD = header bytes.
    Returns (ciphertext, tag) — tag is last 16 bytes of GCM output.
    """
    if len(plaintext) > MAX_MESSAGE_SIZE:
        raise ValueError("ERR_MSG_TOO_LARGE")
    if seq > MAX_SEQ:
        raise ValueError("ERR_SESSION_EXPIRED: seq overflow")

    nonce = _build_nonce(session.base_nonce, seq)
    aesgcm = AESGCM(session.key)
    # GCM returns ciphertext || tag (last 16 bytes)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, header)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return ciphertext, tag


def decrypt_message(session: SessionKeys, seq: int, ciphertext: bytes, tag: bytes, header: bytes) -> bytes:
    """AES-256-GCM decrypt + verify. Raises on tag mismatch."""
    nonce = _build_nonce(session.base_nonce, seq)
    aesgcm = AESGCM(session.key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, header)
    except Exception:
        raise ValueError("ERR_TAG_INVALID: authentication failed")


def hash_document(data: bytes) -> bytes:
    """SHA-256 hash for document signing."""
    return hashlib.sha256(data).digest()


def sign_data(identity: IdentityKeyPair, prefix: bytes, data: bytes) -> bytes:
    """Domain-prefixed Ed25519 signature."""
    return identity.sign(prefix + data)


def verify_signature(public_key_bytes: bytes, signature: bytes, prefix: bytes, data: bytes) -> bool:
    """Verify domain-prefixed Ed25519 signature."""
    return IdentityKeyPair.verify(public_key_bytes, signature, prefix + data)
