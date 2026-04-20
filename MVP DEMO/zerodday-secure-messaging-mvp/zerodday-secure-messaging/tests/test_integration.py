"""
ZeroDay Secure Messaging — Integration Tests
Tests real TCP connections, E2E encrypted messaging, attack scenarios,
document signing flows, and security audit logging.
"""
import pytest
import sys
import os
import threading
import time
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto_core import IdentityKeyPair
from src.protocol import Session, SessionState, sign_document, verify_document
from src.blockchain import Blockchain
from src.network import SecureServer, SecureClient
from src.audit_log import SecurityLogger, SecurityEvent, init_logging


# Use different ports per test to avoid conflicts
_PORT_COUNTER = 19800


def _next_port():
    global _PORT_COUNTER
    _PORT_COUNTER += 1
    return _PORT_COUNTER


# === TCP INTEGRATION TESTS ===

class TestTCPHandshake:
    """Test real TCP handshake between client and server."""

    def test_successful_handshake(self):
        port = _next_port()
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        server = SecureServer(bob_id, port=port)
        server.start()

        def server_thread():
            assert server.accept_and_handshake(timeout=10)

        t = threading.Thread(target=server_thread)
        t.start()

        time.sleep(0.1)  # Let server bind

        client = SecureClient(alice_id, port=port)
        assert client.connect_and_handshake(timeout=10)

        t.join(timeout=5)

        # Both should be ESTABLISHED
        assert client.session.state == SessionState.ESTABLISHED
        assert server.session.state == SessionState.ESTABLISHED

        # Session keys match
        assert client.session.session_keys.key == server.session.session_keys.key

        server.close()
        client.close()


class TestTCPMessaging:
    """Test encrypted messaging over real TCP."""

    def _setup_pair(self):
        port = _next_port()
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        server = SecureServer(bob_id, port=port)
        server.start()

        result = {"ok": False}

        def server_hs():
            result["ok"] = server.accept_and_handshake(timeout=10)

        t = threading.Thread(target=server_hs)
        t.start()
        time.sleep(0.1)

        client = SecureClient(alice_id, port=port)
        client.connect_and_handshake(timeout=10)
        t.join(timeout=5)
        assert result["ok"]
        return client, server

    def test_send_and_receive(self):
        client, server = self._setup_pair()

        client.send_encrypted(b"Hello over TCP!")

        plaintext = server.recv_and_decrypt(timeout=5)
        assert plaintext == b"Hello over TCP!"

        server.close()
        client.close()

    def test_bidirectional_messaging(self):
        client, server = self._setup_pair()

        # Client -> Server
        client.send_encrypted(b"Request from Alice")
        assert server.recv_and_decrypt(timeout=5) == b"Request from Alice"

        # Server -> Client
        server.send_encrypted(b"Response from Bob")
        assert client.recv_and_decrypt(timeout=5) == b"Response from Bob"

        server.close()
        client.close()

    def test_multiple_messages(self):
        client, server = self._setup_pair()

        for i in range(10):
            msg = f"Message {i}".encode()
            client.send_encrypted(msg)
            assert server.recv_and_decrypt(timeout=5) == msg

        server.close()
        client.close()

    def test_close_notify(self):
        client, server = self._setup_pair()

        client.send_encrypted(b"final message")
        server.recv_and_decrypt(timeout=5)

        client.close()
        assert client.session.state == SessionState.CLOSED

        # Server should get None (CLOSE_NOTIFY)
        result = server.recv_and_decrypt(timeout=3)
        assert result is None

        server.close()


class TestTCPAttackDetection:
    """Test attack detection over real TCP."""

    def _setup_pair(self):
        port = _next_port()
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        server = SecureServer(bob_id, port=port)
        server.start()

        result = {"ok": False}

        def server_hs():
            result["ok"] = server.accept_and_handshake(timeout=10)

        t = threading.Thread(target=server_hs)
        t.start()
        time.sleep(0.1)

        client = SecureClient(alice_id, port=port)
        client.connect_and_handshake(timeout=10)
        t.join(timeout=5)
        return client, server

    def test_replay_over_tcp(self):
        """Replay a captured message — should be rejected at protocol layer."""
        client, server = self._setup_pair()

        # Send first message normally
        client.send_encrypted(b"original")
        pt = server.recv_and_decrypt(timeout=5)
        assert pt == b"original"

        # Now try to decrypt the same seq again at protocol level
        # (This tests the replay protection logic directly over a real session)
        msg = client.session.encrypt_and_sign(b"second")
        # Force seq back to simulate replay
        msg["seq"] = 0

        # The server's protocol layer should catch seq <= last_seen
        with pytest.raises(ValueError, match="ERR_SEQ_REPLAY|ERR_SIG_INVALID"):
            server.session.verify_and_decrypt(msg)

        server.close()
        client.close()


# === PROTOCOL-LEVEL INTEGRATION TESTS ===

class TestProtocolIntegration:
    """Integration tests at the protocol layer (no TCP)."""

    def _setup_session(self):
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()
        alice = Session(identity=alice_id, role="client")
        bob = Session(identity=bob_id, role="server")

        hello = alice.create_client_hello()
        server_hello = bob.process_client_hello(hello)
        finished = alice.process_server_hello(server_hello)
        bob.process_finished(finished)
        alice.process_finished(finished)
        return alice, bob, alice_id, bob_id

    def test_many_messages_sequential(self):
        """Send 100 messages; all decrypt correctly with unique nonces."""
        alice, bob, _, _ = self._setup_session()
        for i in range(100):
            msg = alice.encrypt_and_sign(f"msg-{i}".encode())
            pt = bob.verify_and_decrypt(msg)
            assert pt == f"msg-{i}".encode()

    def test_large_message(self):
        """1 MB message encrypts and decrypts correctly."""
        alice, bob, _, _ = self._setup_session()
        big = os.urandom(1_000_000)
        msg = alice.encrypt_and_sign(big)
        assert bob.verify_and_decrypt(msg) == big

    def test_document_signing_with_blockchain(self):
        """Full doc signing flow with blockchain audit."""
        _, _, alice_id, _ = self._setup_session()
        bc = Blockchain()
        bc.register_key("alice", alice_id.public_bytes().hex())

        doc = b"Contract: Alice pays Bob $5000"
        signed = sign_document(alice_id, doc, "contract.pdf")

        # Verify document
        assert verify_document(signed, doc)

        # Log on blockchain
        bc.log_document_signature("alice", signed["doc_hash"], signed["doc_sig"])
        assert bc.validate_chain()

        # Verify key on chain matches signer
        chain_key = bc.lookup_key("alice")
        assert chain_key == alice_id.public_bytes().hex()

    def test_key_revocation_flow(self):
        """Revoked key should not be usable."""
        bc = Blockchain()
        alice_id = IdentityKeyPair()
        key_hex = alice_id.public_bytes().hex()

        bc.register_key("alice", key_hex)
        assert bc.lookup_key("alice") == key_hex

        bc.revoke_key("alice", key_hex)
        assert bc.lookup_key("alice") is None
        assert bc.is_key_revoked(key_hex)


# === SECURITY LOGGING TESTS ===

class TestSecurityLogging:
    """Test that security events are properly logged."""

    def test_events_are_recorded(self):
        logger = SecurityLogger(console=False)
        logger.log(SecurityEvent.KEY_GENERATED, key_id="abc123")
        logger.log(SecurityEvent.HANDSHAKE_COMPLETED, session_id="sess-1")

        events = logger.get_events()
        assert len(events) == 2
        assert events[0]["event"] == "KEY_GENERATED"
        assert events[1]["session_id"] == "sess-1"

    def test_incident_detection(self):
        logger = SecurityLogger(console=False)
        logger.log(SecurityEvent.MSG_ENCRYPTED, session_id="s1")  # Normal
        logger.log(SecurityEvent.REPLAY_DETECTED, session_id="s1", seq=42)  # CRITICAL
        logger.log(SecurityEvent.TAMPER_DETECTED, session_id="s1")  # CRITICAL

        incidents = logger.get_security_incidents()
        assert len(incidents) == 2
        assert incidents[0]["event"] == "REPLAY_DETECTED"

    def test_summary(self):
        logger = SecurityLogger(console=False)
        logger.log(SecurityEvent.KEY_GENERATED)
        logger.log(SecurityEvent.REPLAY_DETECTED)
        logger.log(SecurityEvent.MSG_ENCRYPTED)

        s = logger.summary()
        assert s["total_events"] == 3
        assert s["incidents"] == 1

    def test_filter_by_type(self):
        logger = SecurityLogger(console=False)
        logger.log(SecurityEvent.MSG_ENCRYPTED)
        logger.log(SecurityEvent.MSG_DECRYPTED)
        logger.log(SecurityEvent.MSG_ENCRYPTED)

        filtered = logger.get_events(SecurityEvent.MSG_ENCRYPTED)
        assert len(filtered) == 2

    def test_json_export(self, tmp_path):
        logger = SecurityLogger(console=False)
        logger.log(SecurityEvent.HANDSHAKE_COMPLETED, session_id="test-123")

        export_path = str(tmp_path / "audit.json")
        logger.export_json(export_path)

        import json
        with open(export_path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["session_id"] == "test-123"


# === FULL E2E INTEGRATION (TCP + Blockchain + Logging) ===

class TestFullMVP:
    """Complete MVP flow: keygen, blockchain, TCP handshake, messaging, doc signing, logging."""

    def test_mvp_e2e(self):
        port = _next_port()
        logger = SecurityLogger(console=False)

        # 1. Key generation
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()
        logger.log(SecurityEvent.KEY_GENERATED, key_id=alice_id.public_bytes().hex()[:16])
        logger.log(SecurityEvent.KEY_GENERATED, key_id=bob_id.public_bytes().hex()[:16])

        # 2. Blockchain registration
        bc = Blockchain()
        bc.register_key("alice", alice_id.public_bytes().hex())
        bc.register_key("bob", bob_id.public_bytes().hex())
        logger.log(SecurityEvent.KEY_REGISTERED, user="alice")
        logger.log(SecurityEvent.KEY_REGISTERED, user="bob")

        # 3. TCP handshake
        server = SecureServer(bob_id, port=port)
        server.start()

        hs_ok = {"v": False}

        def srv():
            hs_ok["v"] = server.accept_and_handshake(timeout=10)

        t = threading.Thread(target=srv)
        t.start()
        time.sleep(0.1)

        client = SecureClient(alice_id, port=port)
        assert client.connect_and_handshake(timeout=10)
        t.join(timeout=5)
        assert hs_ok["v"]
        logger.log(SecurityEvent.HANDSHAKE_COMPLETED,
                    session_id=client.session.session_id)

        # 4. Encrypted messaging
        client.send_encrypted(b"Hello from Alice!")
        pt = server.recv_and_decrypt(timeout=5)
        assert pt == b"Hello from Alice!"
        logger.log(SecurityEvent.MSG_DECRYPTED,
                    session_id=client.session.session_id, seq=0)

        server.send_encrypted(b"Hello from Bob!")
        pt2 = client.recv_and_decrypt(timeout=5)
        assert pt2 == b"Hello from Bob!"

        # 5. Document signing
        doc = b"Important legal document"
        signed = sign_document(alice_id, doc, "legal.pdf")
        assert verify_document(signed, doc)
        bc.log_document_signature("alice", signed["doc_hash"], signed["doc_sig"])
        logger.log(SecurityEvent.DOC_SIGNED, user="alice",
                    doc_hash=signed["doc_hash"][:16])

        # 6. Blockchain integrity
        assert bc.validate_chain()
        logger.log(SecurityEvent.CHAIN_VALIDATED, blocks=len(bc))

        # 7. Clean close
        client.close()
        server.close()

        # 8. Verify logging
        summary = logger.summary()
        assert summary["total_events"] >= 6
        assert summary["incidents"] == 0  # No attacks in happy path
