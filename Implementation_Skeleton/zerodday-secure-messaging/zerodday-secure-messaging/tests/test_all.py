"""
ZeroDay Secure Messaging — Unit Tests
Tests crypto core, protocol handshake, message exchange, replay protection,
signature verification, document signing, and blockchain.
"""
import pytest
import sys
import os
import json
import pickle

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto_core import (
    IdentityKeyPair, EphemeralKeyPair, SessionKeys,
    derive_session_keys, encrypt_message, decrypt_message,
    hash_document, sign_data, verify_signature,
    PROTOCOL_SALT, MAX_MESSAGE_SIZE,
)
from src.protocol import (
    Session, SessionState, MessageType,
    sign_document, verify_document,
    frame_message, unframe_message,
)
from src.blockchain import Blockchain


# === CRYPTO CORE TESTS ===

class TestIdentityKeys:
    def test_generate_unique(self):
        k1 = IdentityKeyPair()
        k2 = IdentityKeyPair()
        assert k1.public_bytes() != k2.public_bytes()

    def test_sign_and_verify(self):
        k = IdentityKeyPair()
        data = b"hello world"
        sig = k.sign(data)
        assert IdentityKeyPair.verify(k.public_bytes(), sig, data)

    def test_verify_wrong_data_fails(self):
        k = IdentityKeyPair()
        sig = k.sign(b"original")
        assert not IdentityKeyPair.verify(k.public_bytes(), sig, b"tampered")

    def test_verify_wrong_key_fails(self):
        k1 = IdentityKeyPair()
        k2 = IdentityKeyPair()
        sig = k1.sign(b"data")
        assert not IdentityKeyPair.verify(k2.public_bytes(), sig, b"data")


class TestEphemeralKeys:
    def test_shared_secret_agreement(self):
        alice = EphemeralKeyPair()
        bob = EphemeralKeyPair()
        s1 = alice.compute_shared_secret(bob.public_bytes())
        s2 = bob.compute_shared_secret(alice.public_bytes())
        assert s1 == s2
        assert len(s1) == 32

    def test_fresh_per_session(self):
        k1 = EphemeralKeyPair()
        k2 = EphemeralKeyPair()
        assert k1.public_bytes() != k2.public_bytes()

    def test_destroy_clears_key(self):
        k = EphemeralKeyPair()
        k.destroy()
        assert k._private is None


class TestHKDF:
    def test_derive_produces_correct_lengths(self):
        shared = os.urandom(32)
        keys = derive_session_keys(shared)
        assert len(keys.key) == 32
        assert len(keys.base_nonce) == 12

    def test_key_and_nonce_are_different(self):
        shared = os.urandom(32)
        keys = derive_session_keys(shared)
        # They come from different info strings so should differ
        assert keys.key[:12] != keys.base_nonce

    def test_different_secrets_different_keys(self):
        k1 = derive_session_keys(os.urandom(32))
        k2 = derive_session_keys(os.urandom(32))
        assert k1.key != k2.key

    def test_session_keys_not_serializable(self):
        keys = derive_session_keys(os.urandom(32))
        with pytest.raises(RuntimeError, match="cannot be serialized"):
            pickle.dumps(keys)


class TestAESGCM:
    def setup_method(self):
        self.session = derive_session_keys(os.urandom(32))

    def test_encrypt_decrypt_roundtrip(self):
        pt = b"secret message"
        header = b"header-data"
        ct, tag = encrypt_message(self.session, 0, pt, header)
        result = decrypt_message(self.session, 0, ct, tag, header)
        assert result == pt

    def test_tampered_ciphertext_fails(self):
        pt = b"secret message"
        header = b"header"
        ct, tag = encrypt_message(self.session, 0, pt, header)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF  # Flip a byte
        with pytest.raises(ValueError, match="ERR_TAG_INVALID"):
            decrypt_message(self.session, 0, bytes(tampered), tag, header)

    def test_tampered_header_fails(self):
        pt = b"test"
        header = b"original-header"
        ct, tag = encrypt_message(self.session, 0, pt, header)
        with pytest.raises(ValueError, match="ERR_TAG_INVALID"):
            decrypt_message(self.session, 0, ct, tag, b"modified-header")

    def test_nonce_uniqueness(self):
        """10k messages produce 10k unique nonces (SR-06)."""
        from src.crypto_core import _build_nonce
        nonces = set()
        base = self.session.base_nonce
        for seq in range(10_000):
            n = _build_nonce(base, seq)
            nonces.add(n)
        assert len(nonces) == 10_000

    def test_message_too_large(self):
        big = b"x" * (MAX_MESSAGE_SIZE + 1)
        with pytest.raises(ValueError, match="ERR_MSG_TOO_LARGE"):
            encrypt_message(self.session, 0, big, b"header")


class TestSignatures:
    def test_domain_prefixed_signing(self):
        k = IdentityKeyPair()
        data = b"payload"
        sig = sign_data(k, b"test-prefix", data)
        assert verify_signature(k.public_bytes(), sig, b"test-prefix", data)

    def test_wrong_prefix_fails(self):
        k = IdentityKeyPair()
        sig = sign_data(k, b"prefix-a", b"data")
        assert not verify_signature(k.public_bytes(), sig, b"prefix-b", b"data")


# === PROTOCOL TESTS ===

class TestHandshake:
    def test_full_handshake(self):
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        alice = Session(identity=alice_id, role="client")
        bob = Session(identity=bob_id, role="server")

        # Step 1: Client Hello
        client_hello = alice.create_client_hello()
        assert alice.state == SessionState.HELLO_SENT
        assert client_hello["type"] == "CLIENT_HELLO"

        # Step 2: Server Hello
        server_hello = bob.process_client_hello(client_hello)
        assert bob.state == SessionState.KEY_EXCHANGED

        # Step 3: Client processes Server Hello, sends Finished
        finished = alice.process_server_hello(server_hello)
        assert alice.state == SessionState.KEY_EXCHANGED

        # Step 4: Both process Finished
        bob.process_finished(finished)
        alice.process_finished(finished)
        assert alice.state == SessionState.ESTABLISHED
        assert bob.state == SessionState.ESTABLISHED

        # Verify both derived the same session key
        assert alice.session_keys.key == bob.session_keys.key
        assert alice.session_keys.base_nonce == bob.session_keys.base_nonce

    def test_mitm_key_substitution_detected(self):
        """SR-05: MITM injects rogue ephemeral key."""
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()
        eve_id = IdentityKeyPair()

        alice = Session(identity=alice_id, role="client")
        client_hello = alice.create_client_hello()

        # Eve replaces Alice's ephemeral key with her own
        eve_eph = EphemeralKeyPair()
        client_hello["client_ephemeral_pk"] = __import__("base64").b64encode(eve_eph.public_bytes()).decode()
        # Signature won't match

        bob = Session(identity=bob_id, role="server")
        with pytest.raises(ValueError, match="ERR_SIG_INVALID"):
            bob.process_client_hello(client_hello)


class TestEncryptedMessaging:
    def setup_method(self):
        """Set up an established session between Alice and Bob."""
        self.alice_id = IdentityKeyPair()
        self.bob_id = IdentityKeyPair()
        self.alice = Session(identity=self.alice_id, role="client")
        self.bob = Session(identity=self.bob_id, role="server")

        hello = self.alice.create_client_hello()
        server_hello = self.bob.process_client_hello(hello)
        finished = self.alice.process_server_hello(server_hello)
        self.bob.process_finished(finished)
        self.alice.process_finished(finished)

    def test_send_and_receive(self):
        msg = self.alice.encrypt_and_sign(b"Hello Bob!")
        plaintext = self.bob.verify_and_decrypt(msg)
        assert plaintext == b"Hello Bob!"

    def test_bidirectional(self):
        msg1 = self.alice.encrypt_and_sign(b"Hi Bob")
        assert self.bob.verify_and_decrypt(msg1) == b"Hi Bob"

        msg2 = self.bob.encrypt_and_sign(b"Hi Alice")
        assert self.alice.verify_and_decrypt(msg2) == b"Hi Alice"

    def test_replay_rejected(self):
        """SR-04: Replayed message is rejected."""
        msg = self.alice.encrypt_and_sign(b"msg1")
        self.bob.verify_and_decrypt(msg)  # First time: OK

        with pytest.raises(ValueError, match="ERR_SEQ_REPLAY"):
            self.bob.verify_and_decrypt(msg)  # Replay: rejected

    def test_tampered_ciphertext_rejected(self):
        """SR-08: Tampered ciphertext fails auth tag."""
        msg = self.alice.encrypt_and_sign(b"secret")
        # Tamper with ciphertext
        import base64
        ct = bytearray(base64.b64decode(msg["ciphertext"]))
        ct[0] ^= 0xFF
        msg["ciphertext"] = base64.b64encode(bytes(ct)).decode()

        with pytest.raises(ValueError):
            self.bob.verify_and_decrypt(msg)

    def test_sequence_increments(self):
        msg1 = self.alice.encrypt_and_sign(b"msg1")
        msg2 = self.alice.encrypt_and_sign(b"msg2")
        assert msg1["seq"] == 0
        assert msg2["seq"] == 1


class TestMessageFraming:
    def test_frame_unframe_roundtrip(self):
        original = {"type": "TEST", "data": "hello"}
        framed = frame_message(original)
        parsed, remaining = unframe_message(framed)
        assert parsed == original
        assert remaining == b""


class TestDocumentSigning:
    def test_sign_and_verify(self):
        k = IdentityKeyPair()
        doc = b"Important contract content"
        signed = sign_document(k, doc, "contract.pdf")
        assert verify_document(signed, doc)

    def test_tampered_document_fails(self):
        k = IdentityKeyPair()
        doc = b"Original"
        signed = sign_document(k, doc, "doc.txt")
        assert not verify_document(signed, b"Tampered")

    def test_wrong_signer_fails(self):
        k1 = IdentityKeyPair()
        k2 = IdentityKeyPair()
        doc = b"Document"
        signed = sign_document(k1, doc, "doc.txt")
        # Replace signer public key with k2's
        import base64
        signed["signer_pk"] = base64.b64encode(k2.public_bytes()).decode()
        assert not verify_document(signed, doc)


class TestCloseNotify:
    def test_close_notify(self):
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()
        alice = Session(identity=alice_id, role="client")
        bob = Session(identity=bob_id, role="server")

        hello = alice.create_client_hello()
        server_hello = bob.process_client_hello(hello)
        finished = alice.process_server_hello(server_hello)
        bob.process_finished(finished)
        alice.process_finished(finished)

        close_msg = alice.create_close_notify()
        assert close_msg["type"] == "CLOSE_NOTIFY"
        assert "sender_sig" in close_msg
        assert alice.state == SessionState.CLOSED


# === BLOCKCHAIN TESTS ===

class TestBlockchain:
    def test_genesis_block(self):
        bc = Blockchain()
        assert len(bc) == 1
        assert bc.chain[0].payload["type"] == "GENESIS"

    def test_register_and_lookup(self):
        bc = Blockchain()
        bc.register_key("alice", "aabbcc")
        assert bc.lookup_key("alice") == "aabbcc"

    def test_revoke_key(self):
        bc = Blockchain()
        bc.register_key("alice", "key123")
        bc.revoke_key("alice", "key123")
        assert bc.lookup_key("alice") is None
        assert bc.is_key_revoked("key123")

    def test_chain_integrity(self):
        bc = Blockchain()
        bc.register_key("alice", "key1")
        bc.register_key("bob", "key2")
        bc.log_document_signature("alice", "hash123", "sig456")
        assert bc.validate_chain()

    def test_tampered_chain_detected(self):
        bc = Blockchain()
        bc.register_key("alice", "key1")
        # Tamper with a block
        bc.chain[1].payload["public_key"] = "TAMPERED"
        assert not bc.validate_chain()

    def test_unknown_user_returns_none(self):
        bc = Blockchain()
        assert bc.lookup_key("nobody") is None

    def test_document_audit_trail(self):
        bc = Blockchain()
        bc.log_document_signature("alice", "abc123", "sig789")
        assert len(bc) == 2  # Genesis + doc signature
        assert bc.chain[1].payload["doc_hash"] == "abc123"


# === INTEGRATION TEST ===

class TestEndToEnd:
    def test_full_flow(self):
        """Complete E2E: keygen -> blockchain reg -> handshake -> messaging -> doc signing."""
        bc = Blockchain()

        # 1. Key generation
        alice_id = IdentityKeyPair()
        bob_id = IdentityKeyPair()

        # 2. Register on blockchain
        bc.register_key("alice", alice_id.public_bytes().hex())
        bc.register_key("bob", bob_id.public_bytes().hex())
        assert bc.lookup_key("alice") == alice_id.public_bytes().hex()

        # 3. Handshake
        alice = Session(identity=alice_id, role="client")
        bob = Session(identity=bob_id, role="server")

        hello = alice.create_client_hello()
        server_hello = bob.process_client_hello(hello)
        finished = alice.process_server_hello(server_hello)
        bob.process_finished(finished)
        alice.process_finished(finished)

        # 4. Encrypted messaging
        msg = alice.encrypt_and_sign(b"Transfer $1000 to account 42")
        plaintext = bob.verify_and_decrypt(msg)
        assert plaintext == b"Transfer $1000 to account 42"

        # 5. Document signing
        doc = b"Legal agreement between Alice and Bob"
        signed = sign_document(alice_id, doc, "agreement.pdf")
        assert verify_document(signed, doc)

        # 6. Log on blockchain
        bc.log_document_signature("alice", signed["doc_hash"], signed["doc_sig"])

        # 7. Chain integrity
        assert bc.validate_chain()
        assert len(bc) >= 4  # genesis + 2 keys + 1 doc

        # 8. Close
        close = alice.create_close_notify()
        assert close["type"] == "CLOSE_NOTIFY"
