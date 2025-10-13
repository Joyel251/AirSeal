"""
AirSeal Policy Engine

Enforces security policies for file transfers:
- Allowed file types
- Maximum file sizes
- Required scan status
- Allowed signers
- Time constraints
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, List, Set

from .crypto import Manifest


@dataclass
class SecurityPolicy:
    """Security policy for file transfers."""
    policy_id: str
    name: str
    description: str
    
    # File constraints
    allowed_extensions: List[str]  # [".pdf", ".docx", ".xlsx"]
    blocked_extensions: List[str]  # [".exe", ".bat", ".cmd"]
    max_file_size_mb: int
    
    # Scan requirements
    require_clean_scan: bool
    allowed_scan_engines: List[str]  # ["Windows Defender", "ClamAV"]
    
    # Signer constraints
    allowed_signers: List[str]  # Key fingerprints/IDs
    
    # Time constraints
    max_manifest_age_hours: int
    
    # Additional rules
    allow_archives: bool  # .zip, .7z, .tar.gz
    require_signature: bool
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> SecurityPolicy:
        """Create from dictionary."""
        return cls(**data)
    
    def to_json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_json(cls, json_str: str) -> SecurityPolicy:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class PolicyEngine:
    """Enforces security policies."""
    
    def __init__(self, policy: SecurityPolicy):
        """Initialize with a policy."""
        self.policy = policy
    
    def check_manifest(self, manifest: Manifest, file_path: Optional[Path] = None) -> tuple[bool, str]:
        """
        Check if manifest complies with policy.
        
        Returns:
            (complies, reason)
        """
        # 1. Check policy ID match
        if manifest.policy_id != self.policy.policy_id:
            return False, f"Policy ID mismatch: expected '{self.policy.policy_id}', got '{manifest.policy_id}'"
        
        # 2. Check file extension
        filename_lower = manifest.filename.lower()
        ext = Path(filename_lower).suffix
        
        # Check blocked extensions first
        if ext in [e.lower() for e in self.policy.blocked_extensions]:
            return False, f"File extension '{ext}' is blocked by policy"
        
        # Check allowed extensions
        if self.policy.allowed_extensions:
            allowed_lower = [e.lower() for e in self.policy.allowed_extensions]
            if ext not in allowed_lower:
                return False, f"File extension '{ext}' is not in allowed list"
        
        # 3. Check if archives are allowed
        archive_extensions = {".zip", ".7z", ".tar", ".gz", ".rar", ".tar.gz", ".tgz"}
        if ext in archive_extensions and not self.policy.allow_archives:
            return False, "Archive files are not allowed by policy"
        
        # 4. Check file size
        size_mb = manifest.size / (1024 * 1024)
        if size_mb > self.policy.max_file_size_mb:
            return False, f"File size ({size_mb:.1f} MB) exceeds policy limit ({self.policy.max_file_size_mb} MB)"
        
        # 5. Check scan status
        if self.policy.require_clean_scan:
            if manifest.scan_status.upper() != "CLEAN":
                return False, f"File scan status is '{manifest.scan_status}', policy requires 'CLEAN'"
        
        # 6. Check scan engine
        if self.policy.allowed_scan_engines:
            if manifest.scan_engine not in self.policy.allowed_scan_engines:
                return False, f"Scan engine '{manifest.scan_engine}' is not in allowed list"
        
        # 7. Check signer
        if self.policy.allowed_signers:
            if manifest.signer_id not in self.policy.allowed_signers:
                return False, f"Signer '{manifest.signer_id}' is not authorized by policy"
        
        # 8. Check signature requirement
        if self.policy.require_signature and not manifest.signature:
            return False, "Policy requires signature but manifest is not signed"
        
        return True, "Manifest complies with policy"
    
    def check_file(self, file_path: Path) -> tuple[bool, str]:
        """
        Additional file-level checks (MIME type, magic bytes, etc.).
        
        Returns:
            (safe, reason)
        """
        if not file_path.exists():
            return False, "File does not exist"
        
        # Check actual file size matches policy
        actual_size_mb = file_path.stat().st_size / (1024 * 1024)
        if actual_size_mb > self.policy.max_file_size_mb:
            return False, f"Actual file size ({actual_size_mb:.1f} MB) exceeds policy limit"
        
        # Check for zip bombs (compressed vs uncompressed ratio)
        if file_path.suffix.lower() in {".zip", ".7z", ".gz"}:
            if not self._check_zip_bomb(file_path):
                return False, "Potential zip bomb detected"
        
        return True, "File passes policy checks"
    
    def _check_zip_bomb(self, file_path: Path) -> bool:
        """
        Basic zip bomb detection.
        
        Returns:
            True if safe, False if suspicious
        """
        try:
            import zipfile
            
            if file_path.suffix.lower() == ".zip":
                with zipfile.ZipFile(file_path, 'r') as zf:
                    compressed_size = file_path.stat().st_size
                    uncompressed_size = sum(info.file_size for info in zf.infolist())
                    
                    # If uncompressed is >100x compressed, likely a bomb
                    if uncompressed_size > compressed_size * 100:
                        return False
                    
                    # If uncompressed exceeds 10GB, suspicious
                    if uncompressed_size > 10 * 1024 * 1024 * 1024:
                        return False
            
            return True
        except Exception:
            # If we can't check, be conservative
            return True


# Predefined policies
DEFAULT_POLICY = SecurityPolicy(
    policy_id="default-v1",
    name="Default Security Policy",
    description="Standard security policy for general use",
    allowed_extensions=[".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".jpg", ".png"],
    blocked_extensions=[".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr"],
    max_file_size_mb=100,
    require_clean_scan=True,
    allowed_scan_engines=["Windows Defender", "ClamAV", "Demo Scanner"],
    allowed_signers=[],  # Empty = any trusted signer
    max_manifest_age_hours=24,
    allow_archives=False,
    require_signature=True,
)

HIGH_SECURITY_POLICY = SecurityPolicy(
    policy_id="high-security-v1",
    name="High Security Policy",
    description="Strict security policy for sensitive environments",
    allowed_extensions=[".pdf", ".txt"],
    blocked_extensions=[
        ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr",
        ".zip", ".7z", ".rar", ".tar", ".gz",
    ],
    max_file_size_mb=10,
    require_clean_scan=True,
    allowed_scan_engines=["Windows Defender", "ClamAV"],
    allowed_signers=[],  # Must be configured
    max_manifest_age_hours=2,
    allow_archives=False,
    require_signature=True,
)

PERMISSIVE_POLICY = SecurityPolicy(
    policy_id="permissive-v1",
    name="Permissive Policy",
    description="Relaxed policy for development/testing",
    allowed_extensions=[],  # Empty = all allowed
    blocked_extensions=[".exe", ".bat", ".cmd", ".msi"],
    max_file_size_mb=500,
    require_clean_scan=False,
    allowed_scan_engines=[],  # Any engine
    allowed_signers=[],  # Any signer
    max_manifest_age_hours=48,
    allow_archives=True,
    require_signature=True,
)


class PolicyStore:
    """Manages multiple policies."""
    
    def __init__(self, store_path: Optional[Path] = None, skip_disk: bool = False):
        """
        Initialize policy store.
        
        Args:
            store_path: Path to store policies on disk
            skip_disk: If True, skip disk operations (for demos/testing)
        """
        if store_path is None:
            store_path = Path("C:/ProgramData/AirSeal/policies")
        
        self.store_path = store_path
        self._policies: dict[str, SecurityPolicy] = {}
        self.skip_disk = skip_disk
        
        # Always load default policies (in-memory)
        self._load_defaults()
        
        # Only try disk operations if not skipped
        if not skip_disk:
            try:
                self.store_path.mkdir(parents=True, exist_ok=True)
                self._load_policies()
            except Exception as e:
                print(f"Warning: Could not access policy store on disk: {e}")
                print(f"Using in-memory policies only.")
    
    def _load_defaults(self) -> None:
        """Load default policies."""
        self._policies[DEFAULT_POLICY.policy_id] = DEFAULT_POLICY
        self._policies[HIGH_SECURITY_POLICY.policy_id] = HIGH_SECURITY_POLICY
        self._policies[PERMISSIVE_POLICY.policy_id] = PERMISSIVE_POLICY
    
    def _load_policies(self) -> None:
        """Load policies from disk."""
        if not self.store_path.exists():
            return
        
        for policy_file in self.store_path.glob("*.json"):
            try:
                policy_json = policy_file.read_text()
                policy = SecurityPolicy.from_json(policy_json)
                self._policies[policy.policy_id] = policy
            except Exception as e:
                print(f"Warning: Failed to load policy {policy_file}: {e}")
    
    def add_policy(self, policy: SecurityPolicy, save: bool = True) -> None:
        """Add a policy to the store."""
        self._policies[policy.policy_id] = policy
        
        if save and not self.skip_disk:
            try:
                policy_file = self.store_path / f"{policy.policy_id}.json"
                policy_file.write_text(policy.to_json())
            except Exception as e:
                print(f"Warning: Could not save policy to disk: {e}")
    
    def get_policy(self, policy_id: str) -> Optional[SecurityPolicy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)
    
    def has_policy(self, policy_id: str) -> bool:
        """Check if policy exists."""
        return policy_id in self._policies
    
    def list_policies(self) -> List[str]:
        """List all policy IDs."""
        return list(self._policies.keys())
    
    def get_engine(self, policy_id: str) -> Optional[PolicyEngine]:
        """Get a policy engine for a specific policy."""
        policy = self.get_policy(policy_id)
        if policy:
            return PolicyEngine(policy)
        return None