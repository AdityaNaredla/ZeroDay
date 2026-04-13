# ZeroDay Secure Messaging & Signed Document System

**Team ZeroDay** — Applied Cryptography, Spring 2026  
Spec Version: `w5-baseline` (frozen)

## Architecture

```
src/
├── __init__.py          # Package exports
├── crypto_core.py       # Primitives: X25519, HKDF, AES-GCM, Ed25519, SHA-256
├── protocol.py          # Handshake, message framing, session management, doc signing
└── blockchain.py        # Local blockchain for key registry + audit trail

tests/
└── test_all.py          # 30+ unit tests across all components

demo.py                  # Happy-path demo script (E2E flow)
```

## Cryptographic Primitives

| Primitive | Purpose | Library |
|-----------|---------|---------|
| X25519 | Ephemeral key exchange | `cryptography` |
| HKDF-SHA256 | Session key derivation | `cryptography` |
| AES-256-GCM | Authenticated encryption | `cryptography` |
| Ed25519 | Digital signatures | `cryptography` |
| SHA-256 | Document hashing | `hashlib` |

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/zerodday/secure-messaging.git
cd secure-messaging
pip install -r requirements.txt

# 2. Run tests
python -m pytest tests/ -v

# 3. Run demo
python demo.py
```

## Demo Output

The demo script runs through the complete flow:

1. **Key generation** — Ed25519 identity keys for Alice and Bob
2. **Blockchain registration** — Public keys registered on local chain
3. **Handshake** — TLS-inspired: CLIENT_HELLO → SERVER_HELLO → FINISHED
4. **Encrypted messaging** — AES-256-GCM with Ed25519 signatures
5. **Replay attack** — Detected and rejected (ERR_SEQ_REPLAY)
6. **Ciphertext tampering** — Detected and rejected (ERR_TAG_INVALID)
7. **Document signing** — SHA-256 hash + Ed25519 signature
8. **Blockchain audit** — Document signature logged on-chain
9. **Graceful close** — Signed CLOSE_NOTIFY

## Security Properties

- **Confidentiality**: AES-256-GCM; no plaintext on the wire
- **Integrity**: GCM authentication tags detect any modification
- **Authentication**: Ed25519 signatures on all handshake and message data
- **Non-repudiation**: Digital signatures + blockchain audit trail
- **Forward secrecy**: Ephemeral X25519 keys per session; zeroed after use
- **Replay protection**: Monotonic sequence numbers
- **Secure defaults**: No hardcoded keys; secrets generated at runtime via `os.urandom()`

## Secure Defaults

- All key material is generated at runtime using `os.urandom()` — **nothing is hardcoded**
- Ephemeral keys are zeroed from memory after HKDF derivation
- Session keys are wrapped in `SessionKeys` which blocks serialization (`pickle.dumps()` raises `RuntimeError`)
- Private key files should be stored with `chmod 0600` permissions
- The `.gitignore` excludes `*.pem`, `*.key`, `*.priv` files

## CI Pipeline

GitHub Actions runs on every push/PR to `main`:
- Unit tests across Python 3.10, 3.11, 3.12
- Demo script smoke test
- Hardcoded secrets scan

## Spec Freeze

This implementation follows the `w5-baseline` frozen specification.  
Changes require a `SPEC-CHANGE` issue → Security Lead review → 3/5 team consensus.

## Team

| Name | Role | Component |
|------|------|-----------|
| Aditya Naredla | Security Lead | Handshake, HKDF, Blockchain |
| Uma Viraja | PM | Ed25519 signatures, identity |
| Susmitha Edara | Dev Lead | AES-256-GCM, replay protection |
| Sathwik Boguda | Test Lead | TCP transport, attack simulation |
| Kamal Kuturu | Integration | Document signing, benchmarking |
