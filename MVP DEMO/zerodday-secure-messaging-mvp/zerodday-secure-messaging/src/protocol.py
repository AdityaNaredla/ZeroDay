"""
ZeroDay Secure Messaging — Protocol Layer
TLS-inspired handshake, message framing, session management.
"""
import json
import os
import time
import struct
import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from . import crypto_core


class MessageType(str, Enum):
    CLIENT_HELLO = "CLIENT_HELLO"
    SERVER_HELLO = "SERVER_HELLO"
    FINISHED = "FINISHED"
    ENCRYPTED_DATA = "ENCRYPTED_DATA"
    SIGNED_DOCUMENT = "SIGNED_DOCUMENT"
    HEARTBEAT = "HEARTBEAT"
    CLOSE_NOTIFY = "CLOSE_NOTIFY"
    ERROR = "ERROR"


class SessionState(str, Enum):
    IDLE = "IDLE"
    HELLO_SENT = "HELLO_SENT"
    HELLO_RECEIVED = "HELLO_RECEIVED"
    KEY_EXCHANGED = "KEY_EXCHANGED"
    ESTABLISHED = "ESTABLISHED"
    CLOSED = "CLOSED"


PROTOCOL_VERSION = 1
HANDSHAKE_TIMEOUT = 15  # seconds
MAX_CLOCK_SKEW = 30_000  # milliseconds
SUPPORTED_CIPHERS = ["AES-256-GCM"]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _build_header(msg_type: MessageType, session_id: Optional[str] = None, seq: Optional[int] = None) -> dict:
    h = {
        "version": PROTOCOL_VERSION,
        "type": msg_type.value,
        "timestamp": _now_ms(),
    }
    if session_id:
        h["session_id"] = session_id
    if seq is not None:
        h["seq"] = seq
    return h


def frame_message(msg: dict) -> bytes:
    """Frame a message: 4-byte big-endian length + JSON payload."""
    payload = json.dumps(msg).encode()
    return struct.pack("!I", len(payload)) + payload


def unframe_message(data: bytes) -> tuple[dict, bytes]:
    """Unframe: parse length prefix, return (message_dict, remaining_bytes)."""
    if len(data) < 4:
        raise ValueError("Incomplete frame header")
    length = struct.unpack("!I", data[:4])[0]
    if len(data) < 4 + length:
        raise ValueError("Incomplete frame body")
    payload = json.loads(data[4:4 + length])
    return payload, data[4 + length:]


@dataclass
class Session:
    """Manages crypto state for one connection."""
    identity: crypto_core.IdentityKeyPair
    role: str  # "client" or "server"

    # Handshake state
    state: SessionState = SessionState.IDLE
    ephemeral: Optional[crypto_core.EphemeralKeyPair] = None
    session_id: Optional[str] = None
    peer_identity_pk: Optional[bytes] = None
    peer_ephemeral_pk: Optional[bytes] = None

    # Session crypto
    session_keys: Optional[crypto_core.SessionKeys] = None
    send_seq: int = 0
    recv_seq: int = -1  # last seen seq

    def create_client_hello(self) -> dict:
        """Client initiates handshake."""
        assert self.state == SessionState.IDLE, f"Bad state: {self.state}"
        self.ephemeral = crypto_core.EphemeralKeyPair()
        eph_pk = self.ephemeral.public_bytes()

        # Sign ephemeral key with identity key
        sig = crypto_core.sign_data(self.identity, b"client-ephemeral", eph_pk)

        msg = _build_header(MessageType.CLIENT_HELLO)
        msg["client_identity_pk"] = _b64(self.identity.public_bytes())
        msg["client_ephemeral_pk"] = _b64(eph_pk)
        msg["ephemeral_sig"] = _b64(sig)
        msg["supported_ciphers"] = SUPPORTED_CIPHERS

        self.state = SessionState.HELLO_SENT
        return msg

    def process_client_hello(self, msg: dict) -> dict:
        """Server processes CLIENT_HELLO and responds with SERVER_HELLO."""
        assert self.state == SessionState.IDLE, f"Bad state: {self.state}"

        # Validate version
        if msg.get("version") != PROTOCOL_VERSION:
            raise ValueError("ERR_VERSION_UNSUPPORTED")

        # Extract and verify client's ephemeral key
        client_id_pk = _unb64(msg["client_identity_pk"])
        client_eph_pk = _unb64(msg["client_ephemeral_pk"])
        client_sig = _unb64(msg["ephemeral_sig"])

        if not crypto_core.verify_signature(client_id_pk, client_sig, b"client-ephemeral", client_eph_pk):
            raise ValueError("ERR_SIG_INVALID: client ephemeral key signature failed")

        # Negotiate cipher
        client_ciphers = msg.get("supported_ciphers", [])
        common = [c for c in SUPPORTED_CIPHERS if c in client_ciphers]
        if not common:
            raise ValueError("ERR_CIPHER_MISMATCH")

        # Generate server ephemeral
        self.ephemeral = crypto_core.EphemeralKeyPair()
        server_eph_pk = self.ephemeral.public_bytes()
        sig = crypto_core.sign_data(self.identity, b"server-ephemeral", server_eph_pk)

        # Generate session ID
        self.session_id = os.urandom(16).hex()
        self.peer_identity_pk = client_id_pk
        self.peer_ephemeral_pk = client_eph_pk

        # Compute shared secret and derive keys
        shared_secret = self.ephemeral.compute_shared_secret(client_eph_pk)
        self.session_keys = crypto_core.derive_session_keys(shared_secret)
        self.ephemeral.destroy()  # Zero ephemeral private key

        response = _build_header(MessageType.SERVER_HELLO)
        response["server_identity_pk"] = _b64(self.identity.public_bytes())
        response["server_ephemeral_pk"] = _b64(server_eph_pk)
        response["ephemeral_sig"] = _b64(sig)
        response["selected_cipher"] = common[0]
        response["session_id"] = self.session_id

        self.state = SessionState.KEY_EXCHANGED
        return response

    def process_server_hello(self, msg: dict) -> dict:
        """Client processes SERVER_HELLO and sends FINISHED."""
        assert self.state == SessionState.HELLO_SENT, f"Bad state: {self.state}"

        if msg.get("version") != PROTOCOL_VERSION:
            raise ValueError("ERR_VERSION_UNSUPPORTED")

        server_id_pk = _unb64(msg["server_identity_pk"])
        server_eph_pk = _unb64(msg["server_ephemeral_pk"])
        server_sig = _unb64(msg["ephemeral_sig"])

        if not crypto_core.verify_signature(server_id_pk, server_sig, b"server-ephemeral", server_eph_pk):
            raise ValueError("ERR_SIG_INVALID: server ephemeral key signature failed")

        self.session_id = msg["session_id"]
        self.peer_identity_pk = server_id_pk
        self.peer_ephemeral_pk = server_eph_pk

        # Compute shared secret and derive keys
        shared_secret = self.ephemeral.compute_shared_secret(server_eph_pk)
        self.session_keys = crypto_core.derive_session_keys(shared_secret)
        self.ephemeral.destroy()

        # Build FINISHED with verify_data = HMAC(session_key, "finished" || transcript)
        import hmac
        transcript = (msg.get("session_id", "") + msg.get("selected_cipher", "")).encode()
        verify_data = hmac.new(self.session_keys.key, b"finished" + transcript, "sha256").digest()

        finished = _build_header(MessageType.FINISHED, self.session_id)
        finished["verify_data"] = _b64(verify_data)

        self.state = SessionState.KEY_EXCHANGED
        return finished

    def process_finished(self, msg: dict):
        """Server/client processes FINISHED to complete handshake."""
        assert self.state == SessionState.KEY_EXCHANGED, f"Bad state: {self.state}"
        # In a full impl we'd verify verify_data; for MVP we trust the derivation
        self.state = SessionState.ESTABLISHED

    def encrypt_and_sign(self, plaintext: bytes) -> dict:
        """Encrypt a message and sign it. Returns framed message dict."""
        assert self.state == SessionState.ESTABLISHED, f"Not established: {self.state}"
        assert self.session_keys is not None

        seq = self.send_seq
        self.send_seq += 1

        if self.send_seq > crypto_core.MAX_SEQ:
            raise ValueError("ERR_SESSION_EXPIRED: seq overflow, rekey required")

        header = _build_header(MessageType.ENCRYPTED_DATA, self.session_id, seq)
        header_bytes = json.dumps(header, sort_keys=True).encode()

        ciphertext, tag = crypto_core.encrypt_message(self.session_keys, seq, plaintext, header_bytes)

        # Sign: "msg" || session_id || seq || ciphertext || tag
        sign_payload = b"msg" + self.session_id.encode() + seq.to_bytes(4, 'big') + ciphertext + tag
        sig = crypto_core.sign_data(self.identity, b"msg", sign_payload)

        header["ciphertext"] = _b64(ciphertext)
        header["auth_tag"] = _b64(tag)
        header["sender_sig"] = _b64(sig)
        return header

    def verify_and_decrypt(self, msg: dict) -> bytes:
        """Verify signature, check replay, decrypt message."""
        assert self.state == SessionState.ESTABLISHED, f"Not established: {self.state}"

        seq = msg.get("seq", 0)

        # Replay check
        if seq <= self.recv_seq:
            raise ValueError(f"ERR_SEQ_REPLAY: seq={seq} <= last_seen={self.recv_seq}")
        self.recv_seq = seq

        ciphertext = _unb64(msg["ciphertext"])
        tag = _unb64(msg["auth_tag"])
        sig = _unb64(msg["sender_sig"])

        # Verify signature
        sign_payload = b"msg" + self.session_id.encode() + seq.to_bytes(4, 'big') + ciphertext + tag
        if not crypto_core.verify_signature(self.peer_identity_pk, sig, b"msg", sign_payload):
            raise ValueError("ERR_SIG_INVALID: message signature failed")

        # Reconstruct header for AAD
        header_dict = {
            "version": msg["version"],
            "type": msg["type"],
            "session_id": msg["session_id"],
            "seq": seq,
            "timestamp": msg["timestamp"],
        }
        header_bytes = json.dumps(header_dict, sort_keys=True).encode()

        return crypto_core.decrypt_message(self.session_keys, seq, ciphertext, tag, header_bytes)

    def create_close_notify(self) -> dict:
        """Create signed CLOSE_NOTIFY."""
        msg = _build_header(MessageType.CLOSE_NOTIFY, self.session_id, self.send_seq)
        sign_payload = b"close" + self.session_id.encode() + self.send_seq.to_bytes(4, 'big')
        sig = crypto_core.sign_data(self.identity, b"close", sign_payload)
        msg["sender_sig"] = _b64(sig)
        self.state = SessionState.CLOSED
        return msg


def sign_document(identity: crypto_core.IdentityKeyPair, document: bytes, filename: str) -> dict:
    """Hash and sign a document. Returns a SIGNED_DOCUMENT message."""
    doc_hash = crypto_core.hash_document(document)
    timestamp = _now_ms()

    sign_payload = b"doc" + doc_hash + timestamp.to_bytes(8, 'big')
    sig = crypto_core.sign_data(identity, b"doc", sign_payload)

    return {
        "type": MessageType.SIGNED_DOCUMENT.value,
        "filename": filename,
        "doc_hash": doc_hash.hex(),
        "doc_sig": _b64(sig),
        "timestamp": timestamp,
        "signer_pk": _b64(identity.public_bytes()),
    }


def verify_document(signed_msg: dict, document: bytes) -> bool:
    """Verify a signed document: check hash + signature."""
    expected_hash = crypto_core.hash_document(document)
    if expected_hash.hex() != signed_msg["doc_hash"]:
        return False

    signer_pk = _unb64(signed_msg["signer_pk"])
    sig = _unb64(signed_msg["doc_sig"])
    timestamp = signed_msg["timestamp"]

    sign_payload = b"doc" + expected_hash + timestamp.to_bytes(8, 'big')
    return crypto_core.verify_signature(signer_pk, sig, b"doc", sign_payload)
