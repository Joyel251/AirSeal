"""
AirSeal Certificate System

X.509-style certificates for binding identity to public keys.
Designed for air-gapped environments with physical distribution.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


@dataclass
class SenderIdentity:
    """
    Identity information for a sender/scanning station.
    All fields are cryptographically bound in the certificate.
    """
    # Human-readable identification
    operator_name: str          # "Dr. Sarah Johnson"
    station_id: str             # "Medical-Scan-01"
    organization: str           # "City Hospital"
    department: str             # "IT Security"
    email: Optional[str] = None # "sjohnson@hospital.org"
    
    # Authorization
    permissions: list[str] = None  # ["medical_systems", "patient_records"]
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> SenderIdentity:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Certificate:
    """Certificate binding identity metadata to a public key."""

    version: str = "1.0"
    serial_number: Optional[str] = None
    subject: Optional[Any] = None  # May be SenderIdentity or legacy dict/str
    public_key_pem: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    issuer: Optional[Dict[str, Any]] = None
    issuer_name: Optional[str] = None
    issuer_fingerprint: Optional[str] = None
    not_before: Optional[float] = None
    not_after: Optional[float] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    revoked: bool = False
    revocation_reason: Optional[str] = None
    signature: Optional[str] = None

    _derived_fields: set[str] = field(default_factory=set, init=False, repr=False)
    _explicit_null_fields: set[str] = field(default_factory=set, init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize legacy field formats for compatibility."""
        if isinstance(self.subject, dict):
            try:
                self.subject = SenderIdentity.from_dict(self.subject)
            except TypeError:
                self.subject = SenderIdentity(
                    operator_name=self.subject.get("operator_name") or self.subject.get("name", "Unknown"),
                    station_id=self.subject.get("station_id", "Unknown"),
                    organization=self.subject.get("organization", "Unknown"),
                    department=self.subject.get("department"),
                    email=self.subject.get("email"),
                    permissions=self.subject.get("permissions", []) or [],
                )
        elif isinstance(self.subject, str):
            self.subject = SenderIdentity(
                operator_name=self.subject,
                station_id="Unknown",
                organization="Unknown",
                department=None,
                email=None,
                permissions=[],
            )

        if self.issuer and not self.issuer_name:
            self.issuer_name = self.issuer.get("common_name") or self.issuer.get("name")
            self._derived_fields.add("issuer_name")
        if self.issuer_name and not self.issuer:
            issuer_data = {"common_name": self.issuer_name}
            if self.issuer_fingerprint:
                issuer_data["fingerprint"] = self.issuer_fingerprint
            self.issuer = issuer_data
            self._derived_fields.add("issuer")
        elif self.issuer and self.issuer_fingerprint and not self.issuer.get("fingerprint"):
            self.issuer["fingerprint"] = self.issuer_fingerprint

        if self.not_before is not None and not self.valid_from:
            self.valid_from = datetime.fromtimestamp(self.not_before, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            self._derived_fields.add("valid_from")
        if self.not_after is not None and not self.valid_until:
            self.valid_until = datetime.fromtimestamp(self.not_after, tz=timezone.utc).isoformat().replace("+00:00", "Z")
            self._derived_fields.add("valid_until")

        if self.valid_from and self.not_before is None:
            try:
                self.not_before = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        if self.valid_until and self.not_after is None:
            try:
                self.not_after = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass

    def _subject_dict(self) -> Optional[dict]:
        if isinstance(self.subject, SenderIdentity):
            return self.subject.to_dict()
        if isinstance(self.subject, dict):
            return self.subject
        return None

    def _issuer_dict(self) -> Optional[dict]:
        if isinstance(self.issuer, dict):
            return self.issuer
        if self.issuer_name:
            return {"common_name": self.issuer_name}
        return None

    def is_valid_at(self, timestamp: Optional[float] = None) -> tuple[bool, str]:
        """Return whether the certificate is valid at the supplied timestamp."""
        if timestamp is None:
            timestamp = time.time()

        if self.not_before is not None and self.not_after is not None:
            if timestamp < self.not_before:
                return False, "Certificate not yet valid"
            if timestamp > self.not_after:
                return False, "Certificate has expired"
        elif self.valid_from and self.valid_until:
            try:
                valid_from_dt = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
                valid_until_dt = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
                check_dt = datetime.fromtimestamp(timestamp, tz=valid_from_dt.tzinfo)
            except ValueError:
                return False, "Certificate validity period cannot be parsed"

            if check_dt < valid_from_dt:
                return False, "Certificate not yet valid"
            if check_dt > valid_until_dt:
                return False, "Certificate has expired"

        if self.revoked:
            return False, f"Certificate revoked: {self.revocation_reason or 'Unknown reason'}"

        return True, "Certificate is valid"

    def get_validity_period(self) -> tuple[datetime, datetime]:
        """Return validity window as datetime objects."""
        if self.not_before is not None and self.not_after is not None:
            return (
                datetime.fromtimestamp(self.not_before, tz=timezone.utc),
                datetime.fromtimestamp(self.not_after, tz=timezone.utc),
            )
        if self.valid_from and self.valid_until:
            start = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
            end = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            return start, end
        raise ValueError("No validity period defined")

    def days_until_expiry(self) -> int:
        """Return integer count of days remaining before expiry."""
        _, expiry = self.get_validity_period()
        now = datetime.now(expiry.tzinfo or timezone.utc)
        delta = expiry - now
        return delta.days

    def to_serializable_dict(self, include_signature: bool = True, include_derived: bool = True) -> dict:
        """Return dictionary representation suitable for JSON output."""
        data: Dict[str, Any] = {
            "version": self.version,
            "revoked": self.revoked,
        }

        if self.serial_number:
            data["serial_number"] = self.serial_number
        subject_dict = self._subject_dict()
        if subject_dict:
            data["subject"] = subject_dict
        if self.public_key_pem:
            data["public_key_pem"] = self.public_key_pem
        if self.public_key_fingerprint:
            data["public_key_fingerprint"] = self.public_key_fingerprint
        issuer_dict = self._issuer_dict()
        if issuer_dict and (include_derived or "issuer" not in self._derived_fields):
            data["issuer"] = issuer_dict
        if self.issuer_name and (include_derived or "issuer_name" not in self._derived_fields):
            data["issuer_name"] = self.issuer_name
        if self.issuer_fingerprint:
            data["issuer_fingerprint"] = self.issuer_fingerprint
        if self.not_before is not None:
            data["not_before"] = self.not_before
        if self.not_after is not None:
            data["not_after"] = self.not_after
        if self.valid_from and (include_derived or "valid_from" not in self._derived_fields):
            data["valid_from"] = self.valid_from
        if self.valid_until and (include_derived or "valid_until" not in self._derived_fields):
            data["valid_until"] = self.valid_until
        if self.revocation_reason is not None or "revocation_reason" in self._explicit_null_fields:
            data["revocation_reason"] = self.revocation_reason
        if include_signature and self.signature:
            data["signature"] = self.signature

        for key in self._explicit_null_fields:
            if key not in data:
                data[key] = None

        return data

    def to_canonical_payload(self) -> dict:
        """Return canonical payload used for signing/verification."""
        return self.to_serializable_dict(include_signature=False, include_derived=False)

    def to_canonical_json(self) -> str:
        """Return canonical JSON string for signature operations."""
        return json.dumps(self.to_canonical_payload(), sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict:
        """Return dictionary including signature (if present)."""
        return self.to_serializable_dict(include_signature=True, include_derived=True)

    @classmethod
    def from_dict(cls, data: dict) -> Certificate:
        """Construct certificate from dictionary, normalising fields."""
        payload = dict(data)

        explicit_nulls = {key for key, value in data.items() if value is None}

        subject_data = payload.get("subject")
        if isinstance(subject_data, dict):
            payload["subject"] = SenderIdentity.from_dict(subject_data)

        issuer_data = payload.get("issuer")
        if isinstance(issuer_data, str):
            payload["issuer"] = {"common_name": issuer_data}

        cert = cls(**payload)
        cert._explicit_null_fields = explicit_nulls
        return cert

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> Certificate:
        return cls.from_dict(json.loads(json_str))

    def save(self, file_path: Path) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(self.to_json())

    @classmethod
    def load(cls, file_path: Path) -> Certificate:
        return cls.from_json(file_path.read_text())


class CertificateAuthority:
    """
    Certificate Authority for issuing and managing certificates.
    This would typically be run by organization security admin.
    """
    
    def __init__(self, name: str, private_key: Ed25519PrivateKey, public_key: Ed25519PublicKey):
        """Initialize CA with name and key pair."""
        self.name = name
        self.private_key = private_key
        self.public_key = public_key
        self.fingerprint = self._compute_fingerprint()
        self.issued_certs: Dict[str, Certificate] = {}
    
    def _compute_fingerprint(self) -> str:
        """Compute fingerprint of CA public key."""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(public_bytes).hexdigest()[:16]
    
    def issue_certificate(
        self,
        subject: SenderIdentity,
        public_key: Ed25519PublicKey,
        validity_days: int = 365,
    ) -> Certificate:
        """
        Issue a new certificate for a sender.
        
        Args:
            subject: Identity information
            public_key: Sender's public key
            validity_days: How long cert is valid
            
        Returns:
            Signed certificate
        """
        import secrets
        # Generate serial number
        serial = secrets.token_hex(16)
        
        # Compute public key fingerprint
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()[:16]
        
        # Export public key to PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
        
        # Set validity period
        now = time.time()
        not_before = now
        not_after = now + (validity_days * 24 * 3600)
        valid_from_iso = datetime.fromtimestamp(not_before, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        valid_until_iso = datetime.fromtimestamp(not_after, tz=timezone.utc).isoformat().replace("+00:00", "Z")

        issuer_info = {"common_name": self.name, "fingerprint": self.fingerprint}

        cert = Certificate(
            version="1.1",
            serial_number=serial,
            subject=subject,
            public_key_pem=public_pem,
            public_key_fingerprint=fingerprint,
            issuer=issuer_info,
            issuer_name=self.name,
            issuer_fingerprint=self.fingerprint,
            not_before=not_before,
            not_after=not_after,
            valid_from=valid_from_iso,
            valid_until=valid_until_iso,
            revoked=False,
        )
        
        # Sign certificate
        canonical_json = cert.to_canonical_json()
        signature = self.private_key.sign(canonical_json.encode('utf-8'))
        cert.signature = signature.hex()
        
        # Track issued certificate
        self.issued_certs[serial] = cert
        
        return cert
    
    def revoke_certificate(self, serial_number: str, reason: str) -> bool:
        """
        Revoke a certificate.
        
        Args:
            serial_number: Certificate serial to revoke
            reason: Reason for revocation
            
        Returns:
            True if revoked, False if not found
        """
        if serial_number in self.issued_certs:
            cert = self.issued_certs[serial_number]
            cert.revoked = True
            cert.revocation_reason = reason
            return True
        return False
    
    def export_ca_certificate(self) -> dict:
        """Export CA's own certificate (for distribution to receivers)."""
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode('utf-8')
        
        return {
            "version": "1.1",
            "name": self.name,
            "fingerprint": self.fingerprint,
            "public_key_pem": public_pem,
            "type": "root_ca",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }


class CertificateVerifier:
    """
    Verifies certificates on the receiver side.
    Checks signature, validity, and revocation status.
    """
    
    def __init__(self, trusted_ca_cert: dict):
        """
        Initialize with trusted CA certificate.
        
        Args:
            trusted_ca_cert: CA cert dict from export_ca_certificate()
        """
        self.ca_name = trusted_ca_cert["name"]
        self.ca_fingerprint = trusted_ca_cert["fingerprint"]
        
        # Load CA public key
        ca_pem = trusted_ca_cert["public_key_pem"].encode('utf-8')
        self.ca_public_key = serialization.load_pem_public_key(ca_pem)
        
        # Revocation list (CRL)
        self.revoked_serials: set[str] = set()
    
    def load_crl(self, crl_path: Path) -> None:
        """Load Certificate Revocation List."""
        if not crl_path.exists():
            return
        
        crl_data = json.loads(crl_path.read_text())
        self.revoked_serials = set(crl_data.get("revoked_serials", []))
    
    def verify_certificate(self, cert: Certificate) -> tuple[bool, str]:
        """
        Verify a certificate.
        
        Returns:
            (is_valid, reason)
        """
        # 1. Check issuer matches trusted CA
        issuer_fp = cert.issuer_fingerprint
        if not issuer_fp and cert.issuer:
            issuer_fp = cert.issuer.get("fingerprint")

        if issuer_fp != self.ca_fingerprint:
            return False, f"Certificate not issued by trusted CA (expected {self.ca_fingerprint}, got {issuer_fp})"
        
        # 2. Verify signature
        if not cert.signature:
            return False, "Certificate missing signature"
        canonical_json = cert.to_canonical_json()
        signature_bytes = bytes.fromhex(cert.signature)
        
        try:
            self.ca_public_key.verify(signature_bytes, canonical_json.encode('utf-8'))
        except Exception as e:
            return False, f"Invalid signature: {e}"
        
        # 3. Check validity period
        is_valid_time, time_reason = cert.is_valid_at()
        if not is_valid_time:
            return False, time_reason
        
        # 4. Check revocation list
        if cert.serial_number in self.revoked_serials:
            return False, f"Certificate has been revoked: {cert.revocation_reason or 'Unknown reason'}"
        
        # 5. Check certificate status
        if cert.revoked:
            return False, f"Certificate is marked as revoked: {cert.revocation_reason or 'Unknown reason'}"
        
        return True, "Certificate is valid"
    
    def extract_identity(self, cert: Certificate) -> dict:
        """
        Extract identity information from verified certificate.
        Only call after verify_certificate() returns True!
        
        Returns:
            Dictionary with identity fields
        """
        valid_from, valid_until = cert.get_validity_period()
        days_left = cert.days_until_expiry()

        subject = cert.subject
        if isinstance(subject, dict):
            subject = SenderIdentity.from_dict(subject)

        operator_name = getattr(subject, "operator_name", "Unknown") if subject else "Unknown"
        station_id = getattr(subject, "station_id", "Unknown") if subject else "Unknown"
        organization = getattr(subject, "organization", "Unknown") if subject else "Unknown"
        department = getattr(subject, "department", None) if subject else None
        email = getattr(subject, "email", None) if subject else None
        permissions = getattr(subject, "permissions", []) if subject else []

        issuer_name = cert.issuer_name
        if not issuer_name and cert.issuer:
            issuer_name = cert.issuer.get("common_name") or cert.issuer.get("name")

        return {
            "operator_name": operator_name,
            "station_id": station_id,
            "organization": organization,
            "department": department,
            "email": email,
            "permissions": permissions,
            "fingerprint": cert.public_key_fingerprint,
            "serial_number": cert.serial_number,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_until": valid_until.strftime("%Y-%m-%d"),
            "days_until_expiry": days_left,
            "issuer": issuer_name,
        }


# Example usage
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    
    # 1. Create CA (organization security admin does this once)
    print("=== Setting up Certificate Authority ===")
    ca_key = Ed25519PrivateKey.generate()
    ca_pub = ca_key.public_key()
    ca = CertificateAuthority("City Hospital Root CA", ca_key, ca_pub)
    print(f"[OK] CA created: {ca.name}")
    print(f"[OK] CA fingerprint: {ca.fingerprint}")
    
    # 2. Issue certificate for scanning station (admin does this for each station)
    print("\n=== Issuing Certificate ===")
    sender_key = Ed25519PrivateKey.generate()
    sender_pub = sender_key.public_key()
    
    sender_identity = SenderIdentity(
        operator_name="Dr. Sarah Johnson",
        station_id="Medical-Scan-01",
        organization="City Hospital",
        department="IT Security",
        email="sjohnson@hospital.org",
        permissions=["medical_systems", "patient_records"]
    )
    
    cert = ca.issue_certificate(sender_identity, sender_pub, validity_days=365)
    print(f"[OK] Certificate issued: {cert.serial_number}")
    print(f"[OK] Valid until: {cert.get_validity_period()[1]}")
    print(f"[OK] Operator: {cert.subject.operator_name}")
    
    # 3. Export CA cert for receivers (distribute via CD/USB)
    print("\n=== Exporting CA Certificate ===")
    ca_cert_export = ca.export_ca_certificate()
    print(f"[OK] CA cert exported (distribute to receivers)")
    
    # 4. Verify certificate on receiver side
    print("\n=== Receiver Verification ===")
    verifier = CertificateVerifier(ca_cert_export)
    is_valid, reason = verifier.verify_certificate(cert)
    print(f"Certificate valid: {is_valid} - {reason}")
    
    if is_valid:
        identity = verifier.extract_identity(cert)
        print(f"\n[OK] Verified Identity:")
        print(f"   Operator: {identity['operator_name']}")
        print(f"   Station: {identity['station_id']}")
        print(f"   Organization: {identity['organization']}")
        print(f"   Department: {identity['department']}")
        print(f"   Fingerprint: {identity['fingerprint']}")
        print(f"   Valid until: {identity['valid_until']} ({identity['days_until_expiry']} days left)")
