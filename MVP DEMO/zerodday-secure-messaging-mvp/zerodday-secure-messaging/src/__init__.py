"""ZeroDay Secure Messaging System — MVP Release v0.5"""
__version__ = "0.5.0"

from .crypto_core import (
    IdentityKeyPair, EphemeralKeyPair, SessionKeys,
    derive_session_keys, encrypt_message, decrypt_message,
    hash_document, sign_data, verify_signature,
)
from .protocol import Session, SessionState, MessageType, sign_document, verify_document
from .blockchain import Blockchain
from .audit_log import SecurityLogger, SecurityEvent, init_logging, audit_log
from .network import SecureServer, SecureClient
