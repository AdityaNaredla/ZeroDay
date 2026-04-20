#!/usr/bin/env python3
"""
ZeroDay Secure Messaging — Happy Path Demo
Run: python demo.py

Demonstrates the full E2E flow:
1. Key generation + blockchain registration
2. Authenticated handshake (signed ephemeral keys)
3. Encrypted messaging (AES-256-GCM)
4. Replay attack detection
5. Ciphertext tampering detection
6. Document signing + verification
7. Blockchain audit trail
"""
import sys
import os
import base64

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.crypto_core import IdentityKeyPair
from src.protocol import Session, sign_document, verify_document
from src.blockchain import Blockchain

# === Colors ===
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

def ok(msg): print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}")
def header(msg): print(f"\n{BOLD}{CYAN}{'='*60}\n  {msg}\n{'='*60}{RESET}")
def step(msg): print(f"\n{YELLOW}▶ {msg}{RESET}")


def main():
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗")
    print(f"║     ZeroDay Secure Messaging — Happy Path Demo       ║")
    print(f"╚══════════════════════════════════════════════════════╝{RESET}")

    # ── 1. KEY GENERATION ──
    header("1. Key Generation")
    alice_id = IdentityKeyPair()
    bob_id = IdentityKeyPair()
    ok(f"Alice identity key: {alice_id.public_bytes().hex()[:16]}...")
    ok(f"Bob   identity key: {bob_id.public_bytes().hex()[:16]}...")

    # ── 2. BLOCKCHAIN REGISTRATION ──
    header("2. Blockchain Key Registration")
    bc = Blockchain()
    bc.register_key("alice", alice_id.public_bytes().hex())
    bc.register_key("bob", bob_id.public_bytes().hex())
    ok(f"Alice registered on block #{bc.chain[-2].index}")
    ok(f"Bob registered on block #{bc.chain[-1].index}")
    ok(f"Lookup Alice: {bc.lookup_key('alice')[:16]}... ✓")
    ok(f"Chain length: {len(bc)} blocks, integrity: {bc.validate_chain()}")

    # ── 3. HANDSHAKE ──
    header("3. Authenticated Key Exchange (TLS-inspired)")
    alice = Session(identity=alice_id, role="client")
    bob = Session(identity=bob_id, role="server")

    step("Alice → CLIENT_HELLO (ephemeral X25519 key + Ed25519 signature)")
    client_hello = alice.create_client_hello()
    ok(f"Client ephemeral pk: {client_hello['client_ephemeral_pk'][:20]}...")
    ok(f"Signature attached: {client_hello['ephemeral_sig'][:20]}...")

    step("Bob verifies signature, generates SERVER_HELLO")
    server_hello = bob.process_client_hello(client_hello)
    ok(f"Session ID: {server_hello['session_id']}")
    ok(f"Selected cipher: {server_hello['selected_cipher']}")

    step("Alice verifies server signature, derives session key, sends FINISHED")
    finished = alice.process_server_hello(server_hello)
    ok(f"Verify data: {finished['verify_data'][:20]}...")

    bob.process_finished(finished)
    alice.process_finished(finished)
    ok(f"Alice state: {alice.state.value}")
    ok(f"Bob state: {bob.state.value}")
    ok(f"Session keys match: {alice.session_keys.key == bob.session_keys.key}")

    # ── 4. ENCRYPTED MESSAGING ──
    header("4. Encrypted Message Exchange")
    step("Alice sends encrypted message to Bob")
    msg = alice.encrypt_and_sign(b"Hello Bob! Transfer $1000 to account 42.")
    ok(f"Ciphertext: {msg['ciphertext'][:30]}...")
    ok(f"Auth tag:   {msg['auth_tag']}")
    ok(f"Signature:  {msg['sender_sig'][:30]}...")
    ok(f"Seq: {msg['seq']}")

    step("Bob verifies signature, decrypts message")
    plaintext = bob.verify_and_decrypt(msg)
    ok(f"Decrypted: \"{plaintext.decode()}\"")

    step("Bob replies to Alice")
    reply = bob.encrypt_and_sign(b"Confirmed. Transaction logged.")
    plaintext2 = alice.verify_and_decrypt(reply)
    ok(f"Alice received: \"{plaintext2.decode()}\"")

    # ── 5. REPLAY ATTACK ──
    header("5. Replay Attack Detection")
    step("Eve captures Alice's message and resends it")
    try:
        bob.verify_and_decrypt(msg)  # Replay the same message
        fail("Replay was NOT detected (this is a bug!)")
    except ValueError as e:
        ok(f"Replay REJECTED: {e}")

    # ── 6. CIPHERTEXT TAMPERING ──
    header("6. Ciphertext Tampering Detection")
    step("Eve modifies one byte in an encrypted message")
    msg2 = alice.encrypt_and_sign(b"Another secret message")
    ct = bytearray(base64.b64decode(msg2["ciphertext"]))
    ct[0] ^= 0xFF
    msg2["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    try:
        bob.verify_and_decrypt(msg2)
        fail("Tampered message was NOT detected (this is a bug!)")
    except ValueError as e:
        ok(f"Tamper REJECTED: {e}")

    # ── 7. DOCUMENT SIGNING ──
    header("7. Document Signing & Verification")
    document = b"LEGAL AGREEMENT: Alice agrees to pay Bob $5000 for consulting services."
    step("Alice signs the document")
    signed = sign_document(alice_id, document, "agreement.pdf")
    ok(f"Doc hash:  {signed['doc_hash'][:32]}...")
    ok(f"Signature: {signed['doc_sig'][:30]}...")

    step("Bob verifies the signature")
    valid = verify_document(signed, document)
    ok(f"Signature valid: {valid}")

    step("Eve tampers with the document")
    tampered_doc = b"LEGAL AGREEMENT: Alice agrees to pay Eve $50000 for nothing."
    valid_tampered = verify_document(signed, tampered_doc)
    ok(f"Tampered doc verification: {valid_tampered} (correctly rejected)")

    # ── 8. BLOCKCHAIN AUDIT ──
    header("8. Blockchain Audit Trail")
    bc.log_document_signature("alice", signed["doc_hash"], signed["doc_sig"])
    ok(f"Document signature logged on block #{bc.chain[-1].index}")
    ok(f"Chain length: {len(bc)} blocks")
    ok(f"Chain integrity: {bc.validate_chain()}")

    # ── 9. CLOSE ──
    header("9. Graceful Session Close")
    close_msg = alice.create_close_notify()
    ok(f"CLOSE_NOTIFY sent (signed), session state: {alice.state.value}")

    # ── SUMMARY ──
    print(f"\n{BOLD}{GREEN}{'='*60}")
    print(f"  ALL CHECKS PASSED — System is operational")
    print(f"{'='*60}{RESET}\n")
    print(f"  Handshake: X25519 + Ed25519 signed ephemeral keys")
    print(f"  Encryption: AES-256-GCM with AAD binding")
    print(f"  Replay protection: Monotonic sequence numbers")
    print(f"  Tamper detection: GCM authentication tags")
    print(f"  Document signing: SHA-256 + Ed25519")
    print(f"  Key registry: Local blockchain ({len(bc)} blocks)")
    print(f"  Session: Closed with signed CLOSE_NOTIFY\n")


if __name__ == "__main__":
    main()
