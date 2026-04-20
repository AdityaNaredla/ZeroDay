"""
ZeroDay Secure Messaging — TCP Networking Layer
Real client/server over TCP sockets with length-prefixed message framing.
"""
import socket
import struct
import json
import threading
import time
from typing import Optional, Callable

from . import crypto_core
from .protocol import (
    Session, SessionState, MessageType,
    frame_message, sign_document, verify_document,
    PROTOCOL_VERSION,
)
from .audit_log import audit_log, SecurityEvent


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9876
RECV_BUFFER = 65536
HEARTBEAT_INTERVAL = 10


def _send_msg(sock: socket.socket, msg: dict):
    """Send a length-prefixed JSON message over TCP."""
    payload = json.dumps(msg).encode()
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv_msg(sock: socket.socket, timeout: float = 30.0) -> Optional[dict]:
    """Receive a length-prefixed JSON message from TCP."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk
        length = struct.unpack("!I", header)[0]

        body = b""
        while len(body) < length:
            chunk = sock.recv(min(length - len(body), RECV_BUFFER))
            if not chunk:
                return None
            body += chunk
        return json.loads(body)
    except socket.timeout:
        return None
    except Exception:
        return None


class SecureServer:
    """TCP server that performs handshake and handles encrypted messages."""

    def __init__(self, identity: crypto_core.IdentityKeyPair, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.identity = identity
        self.host = host
        self.port = port
        self.session: Optional[Session] = None
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._client_socket: Optional[socket.socket] = None
        self.on_message: Optional[Callable[[bytes], Optional[bytes]]] = None

    def start(self):
        """Start server and wait for one client connection."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(1)
        self._running = True

        key_id = self.identity.public_bytes().hex()[:16]
        audit_log.log(SecurityEvent.SESSION_CREATED, key_id=key_id, role="server",
                      address=f"{self.host}:{self.port}")

    def accept_and_handshake(self, timeout: float = 15.0) -> bool:
        """Accept a connection and perform handshake. Returns True on success."""
        self._server_socket.settimeout(timeout)
        try:
            self._client_socket, addr = self._server_socket.accept()
            audit_log.log(SecurityEvent.HANDSHAKE_STARTED, role="server",
                          peer=f"{addr[0]}:{addr[1]}")

            # Receive CLIENT_HELLO
            client_hello = _recv_msg(self._client_socket, timeout=timeout)
            if not client_hello:
                audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="no CLIENT_HELLO received")
                return False

            # Process and respond
            self.session = Session(identity=self.identity, role="server")
            try:
                server_hello = self.session.process_client_hello(client_hello)
            except ValueError as e:
                err_str = str(e)
                if "SIG_INVALID" in err_str:
                    audit_log.log(SecurityEvent.MITM_DETECTED, reason=err_str)
                elif "CIPHER_MISMATCH" in err_str:
                    audit_log.log(SecurityEvent.CIPHER_MISMATCH, reason=err_str)
                else:
                    audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason=err_str)
                return False

            audit_log.log(SecurityEvent.SIG_VERIFIED, session_id=self.session.session_id,
                          detail="client ephemeral key signature valid")
            audit_log.log(SecurityEvent.CIPHER_NEGOTIATED, session_id=self.session.session_id,
                          cipher="AES-256-GCM")

            _send_msg(self._client_socket, server_hello)

            # Receive FINISHED
            finished = _recv_msg(self._client_socket, timeout=timeout)
            if not finished:
                audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="no FINISHED received")
                return False

            self.session.process_finished(finished)
            audit_log.log(SecurityEvent.HANDSHAKE_COMPLETED,
                          session_id=self.session.session_id,
                          version=PROTOCOL_VERSION)
            audit_log.log(SecurityEvent.KEY_ZEROED, detail="ephemeral X25519 private key destroyed")
            return True

        except socket.timeout:
            audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="timeout")
            return False

    def recv_and_decrypt(self, timeout: float = 30.0) -> Optional[bytes]:
        """Receive and decrypt one message."""
        msg = _recv_msg(self._client_socket, timeout=timeout)
        if not msg:
            return None

        msg_type = msg.get("type")

        if msg_type == MessageType.CLOSE_NOTIFY.value:
            audit_log.log(SecurityEvent.SESSION_CLOSED, session_id=self.session.session_id,
                          reason="peer sent CLOSE_NOTIFY")
            return None

        if msg_type == MessageType.ENCRYPTED_DATA.value:
            try:
                plaintext = self.session.verify_and_decrypt(msg)
                audit_log.log(SecurityEvent.MSG_DECRYPTED, session_id=self.session.session_id,
                              seq=msg.get("seq"), size=len(plaintext))
                audit_log.log(SecurityEvent.MSG_VERIFIED, session_id=self.session.session_id,
                              seq=msg.get("seq"))
                return plaintext
            except ValueError as e:
                err_str = str(e)
                if "REPLAY" in err_str:
                    audit_log.log(SecurityEvent.REPLAY_DETECTED,
                                  session_id=self.session.session_id,
                                  seq=msg.get("seq"), detail=err_str)
                elif "TAG_INVALID" in err_str:
                    audit_log.log(SecurityEvent.TAMPER_DETECTED,
                                  session_id=self.session.session_id,
                                  seq=msg.get("seq"), detail=err_str)
                elif "SIG_INVALID" in err_str:
                    audit_log.log(SecurityEvent.SIG_FAILED,
                                  session_id=self.session.session_id,
                                  seq=msg.get("seq"), detail=err_str)
                raise
        return None

    def send_encrypted(self, plaintext: bytes):
        """Encrypt and send a message."""
        msg = self.session.encrypt_and_sign(plaintext)
        audit_log.log(SecurityEvent.MSG_ENCRYPTED, session_id=self.session.session_id,
                      seq=msg["seq"], size=len(plaintext))
        _send_msg(self._client_socket, msg)

    def close(self):
        """Send CLOSE_NOTIFY and shut down."""
        if self.session and self.session.state == SessionState.ESTABLISHED:
            close_msg = self.session.create_close_notify()
            try:
                _send_msg(self._client_socket, close_msg)
            except Exception:
                pass
            audit_log.log(SecurityEvent.SESSION_CLOSED, session_id=self.session.session_id,
                          reason="server initiated close")
        if self._client_socket:
            self._client_socket.close()
        if self._server_socket:
            self._server_socket.close()
        self._running = False


class SecureClient:
    """TCP client that performs handshake and sends encrypted messages."""

    def __init__(self, identity: crypto_core.IdentityKeyPair, host=DEFAULT_HOST, port=DEFAULT_PORT):
        self.identity = identity
        self.host = host
        self.port = port
        self.session: Optional[Session] = None
        self._socket: Optional[socket.socket] = None

    def connect_and_handshake(self, timeout: float = 15.0) -> bool:
        """Connect to server and perform handshake."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)

        try:
            self._socket.connect((self.host, self.port))
            self.session = Session(identity=self.identity, role="client")

            audit_log.log(SecurityEvent.HANDSHAKE_STARTED, role="client",
                          peer=f"{self.host}:{self.port}")

            # Send CLIENT_HELLO
            client_hello = self.session.create_client_hello()
            _send_msg(self._socket, client_hello)

            # Receive SERVER_HELLO
            server_hello = _recv_msg(self._socket, timeout=timeout)
            if not server_hello:
                audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="no SERVER_HELLO")
                return False

            try:
                finished = self.session.process_server_hello(server_hello)
            except ValueError as e:
                err_str = str(e)
                if "SIG_INVALID" in err_str:
                    audit_log.log(SecurityEvent.MITM_DETECTED, reason=err_str)
                else:
                    audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason=err_str)
                return False

            audit_log.log(SecurityEvent.SIG_VERIFIED, session_id=self.session.session_id,
                          detail="server ephemeral key signature valid")

            # Send FINISHED
            _send_msg(self._socket, finished)
            self.session.process_finished(finished)

            audit_log.log(SecurityEvent.HANDSHAKE_COMPLETED,
                          session_id=self.session.session_id,
                          version=PROTOCOL_VERSION)
            audit_log.log(SecurityEvent.KEY_ZEROED, detail="ephemeral X25519 private key destroyed")
            return True

        except socket.timeout:
            audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="connection timeout")
            return False
        except ConnectionRefusedError:
            audit_log.log(SecurityEvent.HANDSHAKE_FAILED, reason="connection refused")
            return False

    def send_encrypted(self, plaintext: bytes):
        """Encrypt and send a message."""
        msg = self.session.encrypt_and_sign(plaintext)
        audit_log.log(SecurityEvent.MSG_ENCRYPTED, session_id=self.session.session_id,
                      seq=msg["seq"], size=len(plaintext))
        _send_msg(self._socket, msg)

    def recv_and_decrypt(self, timeout: float = 30.0) -> Optional[bytes]:
        """Receive and decrypt one message."""
        msg = _recv_msg(self._socket, timeout=timeout)
        if not msg:
            return None

        if msg.get("type") == MessageType.CLOSE_NOTIFY.value:
            audit_log.log(SecurityEvent.SESSION_CLOSED, session_id=self.session.session_id,
                          reason="peer sent CLOSE_NOTIFY")
            return None

        if msg.get("type") == MessageType.ENCRYPTED_DATA.value:
            try:
                plaintext = self.session.verify_and_decrypt(msg)
                audit_log.log(SecurityEvent.MSG_DECRYPTED, session_id=self.session.session_id,
                              seq=msg.get("seq"), size=len(plaintext))
                return plaintext
            except ValueError as e:
                err_str = str(e)
                if "REPLAY" in err_str:
                    audit_log.log(SecurityEvent.REPLAY_DETECTED,
                                  session_id=self.session.session_id, detail=err_str)
                elif "TAG_INVALID" in err_str:
                    audit_log.log(SecurityEvent.TAMPER_DETECTED,
                                  session_id=self.session.session_id, detail=err_str)
                raise
        return None

    def close(self):
        """Send CLOSE_NOTIFY and disconnect."""
        if self.session and self.session.state == SessionState.ESTABLISHED:
            close_msg = self.session.create_close_notify()
            try:
                _send_msg(self._socket, close_msg)
            except Exception:
                pass
            audit_log.log(SecurityEvent.SESSION_CLOSED, session_id=self.session.session_id,
                          reason="client initiated close")
        if self._socket:
            self._socket.close()
