# ZeroDay Secure Messaging — Operations Runbook

## Release: `v0.5-mvp` (tag: `v0.5-mvp`)

## Environment Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10, 3.11, or 3.12 | Tested on all three |
| OS | Linux, macOS, Windows | TCP sockets are cross-platform |
| `cryptography` | ≥42.0.0 | X25519, Ed25519, AES-GCM, HKDF |
| `pytest` | ≥8.0.0 | Testing only |
| Network | Loopback (127.0.0.1) | Default; configurable host/port |
| Disk | <10 MB | No persistent storage required |

## Setup

```bash
# Clone
git clone https://github.com/zerodday/secure-messaging.git
cd secure-messaging

# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "from src import __version__; print(f'ZeroDay v{__version__}')"
# Expected: ZeroDay v0.5.0
```

## Running Tests

```bash
# All unit tests (38 tests)
python -m pytest tests/test_all.py -v

# Integration tests (TCP, E2E, logging)
python -m pytest tests/test_integration.py -v

# All tests together
python -m pytest tests/ -v

# With coverage (requires pytest-cov)
pip install pytest-cov
python -m pytest tests/ --cov=src --cov-report=term-missing
```

## Running the Demo

```bash
# Happy-path demo (no network — in-process simulation)
python demo.py

# TCP demo (real client/server on localhost)
python demo_tcp.py
```

### Expected Demo Output

The demo should complete with `ALL CHECKS PASSED` and show:
- Key generation (2 Ed25519 identity keys)
- Blockchain registration (2 keys registered)
- Handshake (CLIENT_HELLO → SERVER_HELLO → FINISHED → ESTABLISHED)
- Encrypted messaging (AES-256-GCM, bidirectional)
- Replay attack rejected (ERR_SEQ_REPLAY)
- Ciphertext tamper rejected (ERR_TAG_INVALID or ERR_SIG_INVALID)
- Document signed and verified
- Blockchain audit trail validated
- Session closed with signed CLOSE_NOTIFY

## Creating the Release Tag

```bash
git add -A
git commit -m "MVP release: E2E secure messaging with tests and CI"
git tag -a v0.5-mvp -m "MVP: handshake + encryption + signing + blockchain + tests"
git push origin main --tags
```

## Configuration

All configuration is via constructor arguments; no config files or environment variables are required for the MVP.

| Parameter | Default | Where |
|---|---|---|
| `host` | `127.0.0.1` | `SecureServer`, `SecureClient` |
| `port` | `9876` | `SecureServer`, `SecureClient` |
| `timeout` | `15s` (handshake), `30s` (messages) | Method arguments |
| `log_file` | `None` (memory only) | `init_logging()` |

### Enabling File-Based Audit Logging

```python
from src.audit_log import init_logging
logger = init_logging(log_file="logs/audit.log", console=True)
```

Logs are JSON-structured with timestamp, event type, severity, session ID, and details.

## Security Checklist

- [ ] No private keys in the repository (check with `git log --all -p | grep -i "private"`)
- [ ] `.gitignore` excludes `*.pem`, `*.key`, `*.priv`
- [ ] All keys generated at runtime via `os.urandom()`
- [ ] Ephemeral keys zeroed after HKDF derivation
- [ ] `SessionKeys` blocks pickle serialization
- [ ] Nonce construction: `base_nonce XOR seq` (no manual nonce API)
- [ ] GCM auth tag verified before decryption (library enforces)
- [ ] Replay protection via monotonic sequence numbers
- [ ] Signatures domain-prefixed to prevent cross-context reuse

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: cryptography` | Missing dependency | `pip install -r requirements.txt` |
| `Address already in use` | Port conflict | Change port or wait 60s for TIME_WAIT |
| `ERR_HANDSHAKE_TIMEOUT` | Slow network/system | Increase timeout parameter |
| `Connection refused` | Server not started | Start server before client connects |
| Test flakiness | Port reuse between tests | Tests use incrementing ports; re-run |

## Architecture Summary

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│   Alice      │  TCP    │  Untrusted       │  TCP    │   Bob        │
│  (Client)    │◄──────►│  Network         │◄──────►│  (Server)    │
│              │         │  (Eve may lurk)  │         │              │
│ ┌──────────┐ │         └──────────────────┘         │ ┌──────────┐ │
│ │ crypto   │ │                                      │ │ crypto   │ │
│ │ _core.py │ │   Handshake: X25519 + Ed25519       │ │ _core.py │ │
│ ├──────────┤ │   Messages:  AES-256-GCM + sigs     │ ├──────────┤ │
│ │ protocol │ │   Docs:      SHA-256 + Ed25519      │ │ protocol │ │
│ │ .py      │ │   Registry:  Blockchain             │ │ .py      │ │
│ ├──────────┤ │                                      │ ├──────────┤ │
│ │ network  │ │                                      │ │ network  │ │
│ │ .py      │ │                                      │ │ .py      │ │
│ ├──────────┤ │                                      │ ├──────────┤ │
│ │ audit_log│ │                                      │ │ audit_log│ │
│ └──────────┘ │                                      │ └──────────┘ │
└─────────────┘                                      └─────────────┘
```
