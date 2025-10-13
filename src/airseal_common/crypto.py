"""
AirSeal Cryptographic Core

Implements:
- Ed25519 signing and verification
- Canonical JSON serialization (JCS)
- Nonce generation and validation
- Trust store management
- Manifest signing/verification with anti-replay
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    raise ImportError(
        "cryptography library required. Install with: pip install cryptography"
    )


# Constants
NONCE_BYTES = 32
MAX_MANIFEST_AGE_HOURS = 24
MANIFEST_TIME_TOLERANCE_MINUTES = 15
TRUST_STORE_PATH = Path("C:/ProgramData/AirSeal/trust")
RECEIPTS_PATH = Path("C:/ProgramData/AirSeal/receipts")
USED_MANIFESTS_PATH = Path("C:/ProgramData/AirSeal/used_manifests")


@dataclass
class NonceData:
    """Nonce for anti-replay protection."""
    nonce: str  # hex-encoded random bytes
    transfer_id: str  # unique transfer identifier
    created_at: float  # Unix timestamp
    
    def is_expired(self, max_age_minutes: int = 30) -> bool:
        """Check if nonce is expired."""
        age_seconds = time.time() - self.created_at
        return age_seconds > (max_age_minutes * 60)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ScanResult:
    """File scan results."""
    status: str  # "Clean", "Infected", "Error"
    engine: str  # "Windows Defender", "ClamAV", etc.
    details: str  # Additional info
    timestamp: float


@dataclass
class Manifest:
    """Canonical manifest structure."""
    # Core file identity
    filename: str
    size: int
    sha256: str
    
    # Scan results
    scan_status: str
    scan_engine: str
    scan_details: str
    
    # Metadata
    timestamp: float
    signer_id: str  # Key fingerprint or cert ID
    policy_id: str
    nonce: str
    transfer_id: str
    
    # Signature (added after signing)
    signature: Optional[str] = None
    
    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Convert to canonical dictionary for signing.
        Fields are sorted alphabetically.
        """
        data = {
            "filename": self.filename,
            "nonce": self.nonce,
            "policy_id": self.policy_id,
            "scan_details": self.scan_details,
            "scan_engine": self.scan_engine,
            "scan_status": self.scan_status,
            "sha256": self.sha256,
            "signer_id": self.signer_id,
            "size": self.size,
            "timestamp": self.timestamp,
            "transfer_id": self.transfer_id,
        }
        return data
    
    def to_canonical_json(self) -> str:
        """
        Convert to canonical JSON for signing.
        Uses sorted keys and compact encoding.
        """
        data = self.to_canonical_dict()
        return json.dumps(data, sort_keys=True, separators=(',', ':'))


@dataclass
class ImportReceipt:
    """Receipt for successful import."""
    result: str  # "SUCCESS" or "REJECTED"
    sha256: str
    filename: str
    timestamp: float
    transfer_id: str
    verifier_id: str  # Receiver's key fingerprint
    reason: Optional[str] = None
    signature: Optional[str] = None
    
    def to_canonical_json(self) -> str:
        """Convert to canonical JSON for signing."""
        data = {
            "filename": self.filename,
            "reason": self.reason or "",
            "result": self.result,
            "sha256": self.sha256,
            "timestamp": self.timestamp,
            "transfer_id": self.transfer_id,
            "verifier_id": self.verifier_id,
        }
        return json.dumps(data, sort_keys=True, separators=(',', ':'))


class KeyPair:
    """Ed25519 key pair for signing and verification."""
    
    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        """Initialize with existing key or generate new one."""
        if private_key is None:
            self.private_key = Ed25519PrivateKey.generate()
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()
    
    @classmethod
    def generate(cls) -> KeyPair:
        """Generate a new key pair."""
        return cls()
    
    @classmethod
    def from_private_pem(cls, pem_data: bytes, password: Optional[bytes] = None) -> KeyPair:
        """Load private key from PEM format."""
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Key is not an Ed25519 private key")
        return cls(private_key)
    
    @classmethod
    def from_public_pem(cls, pem_data: bytes) -> Ed25519PublicKey:
        """Load public key from PEM format."""
        public_key = serialization.load_pem_public_key(pem_data)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Key is not an Ed25519 public key")
        return public_key
    
    def get_fingerprint(self) -> str:
        """Get SHA256 fingerprint of public key."""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(public_bytes).hexdigest()[:16]
    
    def export_private_pem(self, password: Optional[bytes] = None) -> bytes:
        """Export private key to PEM format."""
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    
    def export_public_pem(self) -> bytes:
        """Export public key to PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message."""
        return self.private_key.sign(message)
    
    @staticmethod
    def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        """Verify a signature."""
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False


class TrustStore:
    """Manages trusted public keys."""
    
    def __init__(self, store_path: Optional[Path] = None):
        """Initialize trust store."""
        self.store_path = store_path or TRUST_STORE_PATH
        self.store_path.mkdir(parents=True, exist_ok=True)
        self._keys: Dict[str, Ed25519PublicKey] = {}
        self._load_keys()
    
    def _load_keys(self) -> None:
        """Load all trusted keys from store."""
        for key_file in self.store_path.glob("*.pem"):
            try:
                key_id = key_file.stem
                pem_data = key_file.read_bytes()
                public_key = KeyPair.from_public_pem(pem_data)
                self._keys[key_id] = public_key
            except Exception as e:
                print(f"Warning: Failed to load key {key_file}: {e}")
    
    def add_key(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        """Add a trusted key."""
        self._keys[key_id] = public_key
        
        # Save to disk
        key_file = self.store_path / f"{key_id}.pem"
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_file.write_bytes(pem_data)
    
    def get_key(self, key_id: str) -> Optional[Ed25519PublicKey]:
        """Get a trusted key by ID."""
        return self._keys.get(key_id)
    
    def has_key(self, key_id: str) -> bool:
        """Check if key is trusted."""
        return key_id in self._keys
    
    def list_keys(self) -> list[str]:
        """List all trusted key IDs."""
        return list(self._keys.keys())


class NonceManager:
    """Manages nonces for anti-replay protection."""
    
    def __init__(self):
        """Initialize nonce manager."""
        self._active_nonces: Dict[str, NonceData] = {}
    
    def generate_nonce(self) -> NonceData:
        """Generate a new nonce and transfer ID."""
        nonce = secrets.token_hex(NONCE_BYTES)
        transfer_id = secrets.token_hex(16)
        
        nonce_data = NonceData(
            nonce=nonce,
            transfer_id=transfer_id,
            created_at=time.time(),
        )
        
        self._active_nonces[transfer_id] = nonce_data
        return nonce_data
    
    def validate_nonce(self, transfer_id: str, nonce: str, max_age_minutes: int = 30) -> bool:
        """Validate a nonce."""
        nonce_data = self._active_nonces.get(transfer_id)
        
        if nonce_data is None:
            return False
        
        if nonce_data.is_expired(max_age_minutes):
            return False
        
        if nonce_data.nonce != nonce:
            return False
        
        return True
    
    def consume_nonce(self, transfer_id: str) -> bool:
        """Mark nonce as used (one-time use)."""
        if transfer_id in self._active_nonces:
            del self._active_nonces[transfer_id]
            return True
        return False
    
    def cleanup_expired(self, max_age_minutes: int = 30) -> int:
        """Remove expired nonces. Returns count removed."""
        expired = [
            tid for tid, nonce_data in self._active_nonces.items()
            if nonce_data.is_expired(max_age_minutes)
        ]
        for tid in expired:
            del self._active_nonces[tid]
        return len(expired)


class ManifestVerifier:
    """Verifies signed manifests."""
    
    def __init__(self, trust_store: TrustStore, nonce_manager: NonceManager):
        """Initialize verifier."""
        self.trust_store = trust_store
        self.nonce_manager = nonce_manager
        self.used_manifests_path = USED_MANIFESTS_PATH
        self.used_manifests_path.mkdir(parents=True, exist_ok=True)
    
    def verify_manifest(
        self,
        manifest: Manifest,
        check_nonce: bool = True,
        one_time_use: bool = True,
    ) -> tuple[bool, str]:
        """
        Verify a manifest.
        
        Returns:
            (success, error_message)
        """
        # 1. Check signature exists
        if not manifest.signature:
            return False, "Manifest has no signature"
        
        # 2. Check signer is trusted
        if not self.trust_store.has_key(manifest.signer_id):
            return False, f"Signer '{manifest.signer_id}' is not trusted"
        
        # 3. Verify signature
        public_key = self.trust_store.get_key(manifest.signer_id)
        canonical_json = manifest.to_canonical_json()
        signature_bytes = bytes.fromhex(manifest.signature)
        
        if not KeyPair.verify(public_key, signature_bytes, canonical_json.encode()):
            return False, "Invalid signature"
        
        # 4. Check timestamp (with tolerance for clock drift)
        manifest_time = datetime.fromtimestamp(manifest.timestamp)
        now = datetime.now()
        age = now - manifest_time
        
        if age.total_seconds() > (MAX_MANIFEST_AGE_HOURS * 3600):
            return False, f"Manifest is too old ({age.total_seconds() / 3600:.1f} hours)"
        
        # Allow some future time for clock drift
        if manifest_time > now + timedelta(minutes=MANIFEST_TIME_TOLERANCE_MINUTES):
            return False, "Manifest timestamp is too far in the future"
        
        # 5. Validate nonce (anti-replay)
        if check_nonce:
            if not self.nonce_manager.validate_nonce(manifest.transfer_id, manifest.nonce):
                return False, "Invalid or expired nonce"
        
        # 6. Check one-time use
        if one_time_use:
            manifest_id = hashlib.sha256(manifest.signature.encode()).hexdigest()
            used_file = self.used_manifests_path / f"{manifest_id}.used"
            
            if used_file.exists():
                return False, "Manifest has already been used"
            
            # Mark as used
            used_file.write_text(json.dumps({
                "transfer_id": manifest.transfer_id,
                "sha256": manifest.sha256,
                "used_at": time.time(),
            }))
        
        # 7. Consume nonce
        if check_nonce:
            self.nonce_manager.consume_nonce(manifest.transfer_id)
        
        return True, "Manifest verified successfully"


class ManifestSigner:
    """Signs manifests."""
    
    def __init__(self, key_pair: KeyPair):
        """Initialize signer."""
        self.key_pair = key_pair
    
    def sign_manifest(self, manifest: Manifest) -> Manifest:
        """Sign a manifest and return it with signature."""
        # Ensure signature is not set
        manifest.signature = None
        
        # Get canonical JSON
        canonical_json = manifest.to_canonical_json()
        
        # Sign
        signature = self.key_pair.sign(canonical_json.encode())
        
        # Set signature
        manifest.signature = signature.hex()
        
        return manifest


class ReceiptSigner:
    """Signs import receipts."""
    
    def __init__(self, key_pair: KeyPair):
        """Initialize receipt signer."""
        self.key_pair = key_pair
        self.receipts_path = RECEIPTS_PATH
        self.receipts_path.mkdir(parents=True, exist_ok=True)
    
    def sign_receipt(self, receipt: ImportReceipt) -> ImportReceipt:
        """Sign a receipt."""
        receipt.signature = None
        canonical_json = receipt.to_canonical_json()
        signature = self.key_pair.sign(canonical_json.encode())
        receipt.signature = signature.hex()
        return receipt
    
    def save_receipt(self, receipt: ImportReceipt) -> Path:
        """Save a signed receipt to disk."""
        receipt_id = hashlib.sha256(
            f"{receipt.transfer_id}{receipt.timestamp}".encode()
        ).hexdigest()[:16]
        
        receipt_file = self.receipts_path / f"{receipt_id}.json"
        receipt_data = {
            **asdict(receipt),
            "receipt_id": receipt_id,
        }
        receipt_file.write_text(json.dumps(receipt_data, indent=2))
        return receipt_file


def compute_file_hash(file_path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
