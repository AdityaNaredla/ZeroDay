"""
ZeroDay Secure Messaging — Local Blockchain
Single-node append-only chain for key registration and document audit.
"""
import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Block:
    index: int
    timestamp: float
    payload: dict
    previous_hash: str
    block_hash: str = ""

    def compute_hash(self) -> str:
        data = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }, sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()


class Blockchain:
    """Local single-node blockchain for key registration and audit."""

    def __init__(self):
        self.chain: list[Block] = []
        self._create_genesis()

    def _create_genesis(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            payload={"type": "GENESIS", "message": "ZeroDay blockchain initialized"},
            previous_hash="0" * 64,
        )
        genesis.block_hash = genesis.compute_hash()
        self.chain.append(genesis)

    def _add_block(self, payload: dict) -> Block:
        prev = self.chain[-1]
        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            payload=payload,
            previous_hash=prev.block_hash,
        )
        block.block_hash = block.compute_hash()
        self.chain.append(block)
        return block

    def register_key(self, user_id: str, public_key_hex: str) -> Block:
        """Register an Ed25519 public key on-chain."""
        return self._add_block({
            "type": "REGISTER",
            "user_id": user_id,
            "public_key": public_key_hex,
        })

    def revoke_key(self, user_id: str, public_key_hex: str) -> Block:
        """Revoke a previously registered key."""
        return self._add_block({
            "type": "REVOKE",
            "user_id": user_id,
            "public_key": public_key_hex,
        })

    def log_document_signature(self, signer_id: str, doc_hash_hex: str, signature_hex: str) -> Block:
        """Log a document signature on-chain for non-repudiation."""
        return self._add_block({
            "type": "DOC_SIGNATURE",
            "signer_id": signer_id,
            "doc_hash": doc_hash_hex,
            "signature": signature_hex,
        })

    def lookup_key(self, user_id: str) -> Optional[str]:
        """Find the latest active (non-revoked) key for a user."""
        latest_key = None
        revoked_keys = set()

        for block in self.chain:
            p = block.payload
            if p.get("user_id") == user_id:
                if p.get("type") == "REVOKE":
                    revoked_keys.add(p["public_key"])
                elif p.get("type") == "REGISTER":
                    latest_key = p["public_key"]

        if latest_key and latest_key not in revoked_keys:
            return latest_key
        return None

    def is_key_revoked(self, public_key_hex: str) -> bool:
        """Check if a specific key has been revoked."""
        for block in self.chain:
            p = block.payload
            if p.get("type") == "REVOKE" and p.get("public_key") == public_key_hex:
                return True
        return False

    def validate_chain(self) -> bool:
        """Verify chain integrity: each block's hash and linkage."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.block_hash != current.compute_hash():
                return False
            if current.previous_hash != previous.block_hash:
                return False
        return True

    def __len__(self):
        return len(self.chain)
