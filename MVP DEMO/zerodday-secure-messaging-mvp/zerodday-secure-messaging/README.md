# ZeroDay Secure Messaging & Signed Document System

**Team ZeroDay** — Applied Cryptography, Spring 2026
**Release:** `v0.5-mvp` | **Spec:** `w5-baseline` (frozen)

## Quick Start

```bash
pip install -r requirements.txt
python -m pytest tests/ -v        # 54 tests (unit + integration)
python demo.py                    # In-process E2E demo
python demo_tcp.py                # Real TCP client/server demo
```

## Architecture

```
src/
├── crypto_core.py   # X25519, HKDF-SHA256, AES-256-GCM, Ed25519, SHA-256
├── protocol.py      # Handshake FSM, message encrypt/sign, doc signing
├── blockchain.py    # Local chain: key registry + audit trail
├── network.py       # TCP client/server with length-prefixed framing
└── audit_log.py     # Structured security event logging

tests/
├── test_all.py          # 38 unit tests
└── test_integration.py  # 16 integration tests (TCP, E2E, logging)

docs/
└── RUNBOOK.md       # Environment, setup, run steps, troubleshooting
```

## What the MVP Demonstrates

| Feature | Status | Test Coverage |
|---------|--------|---------------|
| X25519 key exchange | ✅ Working | Unit + integration |
| Ed25519 signed handshake | ✅ Working | MITM detection test |
| AES-256-GCM encrypted messaging | ✅ Working | Tamper + replay tests |
| Sequence-based replay protection | ✅ Working | Replay rejection test |
| SHA-256 + Ed25519 document signing | ✅ Working | Sign/verify/tamper tests |
| Blockchain key registry | ✅ Working | Register/revoke/lookup tests |
| TCP client/server | ✅ Working | TCP handshake + messaging tests |
| Security audit logging | ✅ Working | Event recording + export tests |
| Signed CLOSE_NOTIFY | ✅ Working | Session close test |

## Security Properties

- **No hardcoded keys** — all generated at runtime via `os.urandom()`
- **Ephemeral keys zeroed** after HKDF derivation
- **SessionKeys blocks serialization** — `pickle.dumps()` raises `RuntimeError`
- **Nonce = base_nonce XOR seq** — no manual nonce API exposed
- **GCM tag verified before decryption** (library enforces)
- **Domain-prefixed signatures** prevent cross-context reuse
- **Audit logging** records key events, handshakes, failures, and attacks

## Release Tag

```bash
git tag -a v0.5-mvp -m "MVP: E2E secure messaging over TCP with tests and logging"
git push origin main --tags
```

## Team

| Name | Role | Component |
|------|------|-----------|
| Aditya Naredla | Security Lead | Handshake, HKDF, Blockchain |
| Uma Viraja | PM | Ed25519 signatures, identity |
| Susmitha Edara | Dev Lead | AES-256-GCM, replay protection |
| Sathwik Boguda | Test Lead | TCP transport, attack simulation |
| Kamal Kuturu | Integration | Document signing, benchmarking |

See [docs/RUNBOOK.md](docs/RUNBOOK.md) for full operational documentation.
