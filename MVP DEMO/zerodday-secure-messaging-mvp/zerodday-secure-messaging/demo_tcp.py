#!/usr/bin/env python3
"""
ZeroDay Secure Messaging — TCP Demo
Runs a real client/server on localhost with security audit logging.

Usage: python demo_tcp.py
"""
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.crypto_core import IdentityKeyPair
from src.protocol import sign_document, verify_document
from src.blockchain import Blockchain
from src.network import SecureServer, SecureClient
from src.audit_log import SecurityLogger, SecurityEvent

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"; Y = "\033[93m"; B = "\033[1m"; X = "\033[0m"
def ok(m): print(f"  {G}✓{X} {m}")
def hd(m): print(f"\n{B}{C}{'='*60}\n  {m}\n{'='*60}{X}")
def st(m): print(f"\n{Y}▶ {m}{X}")


def main():
    PORT = 19999
    logger = SecurityLogger(console=False)

    print(f"\n{B}{C}╔══════════════════════════════════════════════════════════╗")
    print(f"║   ZeroDay Secure Messaging — TCP Demo (Real Sockets)     ║")
    print(f"╚══════════════════════════════════════════════════════════╝{X}")

    # 1. KEY GENERATION
    hd("1. Key Generation")
    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()
    logger.log(SecurityEvent.KEY_GENERATED, key_id=alice_id.public_bytes().hex()[:16], user="alice")
    logger.log(SecurityEvent.KEY_GENERATED, key_id=bob_id.public_bytes().hex()[:16], user="bob")
    ok(f"Alice key: {alice_id.public_bytes().hex()[:16]}...")
    ok(f"Bob key:   {bob_id.public_bytes().hex()[:16]}...")

    # 2. BLOCKCHAIN
    hd("2. Blockchain Registration")
    bc = Blockchain()
    bc.register_key("alice", alice_id.public_bytes().hex())
    bc.register_key("bob", bob_id.public_bytes().hex())
    logger.log(SecurityEvent.KEY_REGISTERED, user="alice")
    logger.log(SecurityEvent.KEY_REGISTERED, user="bob")
    ok(f"Chain: {len(bc)} blocks, integrity: {bc.validate_chain()}")

    # 3. TCP HANDSHAKE
    hd("3. TCP Handshake (localhost:{PORT})")
    server = SecureServer(bob_id, port=PORT)
    server.start()
    ok("Server listening")

    hs_result = {"ok": False}

    def server_hs():
        hs_result["ok"] = server.accept_and_handshake(timeout=10)

    t = threading.Thread(target=server_hs)
    t.start()
    time.sleep(0.2)

    client = SecureClient(alice_id, port=PORT)
    st("Alice connects and sends CLIENT_HELLO")
    client_ok = client.connect_and_handshake(timeout=10)
    t.join(timeout=5)

    ok(f"Client handshake: {'SUCCESS' if client_ok else 'FAILED'}")
    ok(f"Server handshake: {'SUCCESS' if hs_result['ok'] else 'FAILED'}")
    ok(f"Session ID: {client.session.session_id}")
    ok(f"Keys match: {client.session.session_keys.key == server.session.session_keys.key}")
    logger.log(SecurityEvent.HANDSHAKE_COMPLETED, session_id=client.session.session_id)

    # 4. ENCRYPTED MESSAGING (over TCP)
    hd("4. Encrypted Messaging (TCP)")
    st("Alice → Bob: encrypted message")
    client.send_encrypted(b"Hello Bob! This is Alice over TCP.")
    pt = server.recv_and_decrypt(timeout=5)
    ok(f"Bob decrypted: \"{pt.decode()}\"")
    logger.log(SecurityEvent.MSG_DECRYPTED, session_id=client.session.session_id, seq=0)

    st("Bob → Alice: encrypted reply")
    server.send_encrypted(b"Hi Alice! Secure channel confirmed.")
    pt2 = client.recv_and_decrypt(timeout=5)
    ok(f"Alice decrypted: \"{pt2.decode()}\"")

    st("Sending 5 more messages...")
    for i in range(5):
        client.send_encrypted(f"Message #{i+1}".encode())
        r = server.recv_and_decrypt(timeout=5)
        ok(f"  #{i+1}: \"{r.decode()}\"")

    # 5. DOCUMENT SIGNING
    hd("5. Document Signing")
    doc = b"CONTRACT: Alice agrees to deliver project by April 19, 2026."
    signed = sign_document(alice_id, doc, "contract.pdf")
    ok(f"Signed: hash={signed['doc_hash'][:24]}...")
    assert verify_document(signed, doc)
    ok("Verification: PASSED")

    bc.log_document_signature("alice", signed["doc_hash"], signed["doc_sig"])
    logger.log(SecurityEvent.DOC_SIGNED, user="alice", doc_hash=signed["doc_hash"][:16])
    ok(f"Blockchain audit: logged on block #{bc.chain[-1].index}")

    tampered = b"CONTRACT: Alice agrees to deliver nothing ever."
    assert not verify_document(signed, tampered)
    ok("Tampered doc verification: REJECTED")
    logger.log(SecurityEvent.DOC_TAMPERED, user="eve", detail="hash mismatch")

    # 6. SESSION CLOSE
    hd("6. Graceful Close")
    client.close()
    ok(f"Client state: {client.session.state.value}")
    result = server.recv_and_decrypt(timeout=3)
    ok(f"Server received CLOSE_NOTIFY: {result is None}")
    server.close()
    logger.log(SecurityEvent.SESSION_CLOSED, session_id=client.session.session_id)

    # 7. AUDIT SUMMARY
    hd("7. Security Audit Summary")
    summary = logger.summary()
    ok(f"Total events logged: {summary['total_events']}")
    ok(f"By severity: {summary['by_severity']}")
    ok(f"Security incidents: {summary['incidents']}")

    # Export audit log
    log_path = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(log_path, exist_ok=True)
    export_file = os.path.join(log_path, "demo_audit.json")
    logger.export_json(export_file)
    ok(f"Audit log exported: {export_file}")

    # SUMMARY
    print(f"\n{B}{G}{'='*60}")
    print(f"  MVP DEMO COMPLETE — All systems operational")
    print(f"{'='*60}{X}\n")
    print(f"  Protocol version: 1")
    print(f"  Handshake: X25519 + Ed25519 signed keys (over TCP)")
    print(f"  Encryption: AES-256-GCM with AAD")
    print(f"  Messages exchanged: 7 (bidirectional)")
    print(f"  Document signed + verified + blockchain logged")
    print(f"  Session: closed with signed CLOSE_NOTIFY")
    print(f"  Blockchain: {len(bc)} blocks, integrity verified")
    print(f"  Audit events: {summary['total_events']}, incidents: {summary['incidents']}\n")


if __name__ == "__main__":
    main()
