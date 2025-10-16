"""
Setup script for testing certificate system.

Creates:
1. Root CA certificate
2. One sender certificate for testing
3. Distributes files to test_certificates/ folder
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common.certificates import CertificateAuthority, SenderIdentity, Certificate
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import json


def main():
    print("🔧 AirSeal Certificate Test Setup")
    print("=" * 60)
    
    # Create test_certificates directory
    test_dir = Path(__file__).parent / "test_certificates"
    test_dir.mkdir(exist_ok=True)
    print(f"\n📁 Using directory: {test_dir}")
    
    # Step 1: Create Root CA
    print("\n1️⃣  Creating Root CA...")
    ca_private_key = Ed25519PrivateKey.generate()
    ca_public_key = ca_private_key.public_key()
    
    ca = CertificateAuthority(
        name="AirSeal Test Root CA",
        private_key=ca_private_key,
        public_key=ca_public_key
    )
    
    print(f"   ✓ CA created: {ca.name}")
    print(f"   ✓ CA fingerprint: {ca.fingerprint}")
    
    # Save CA private key (for testing only - in production, store securely!)
    ca_private_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    (test_dir / "ca_private_key.pem").write_bytes(ca_private_pem)
    print(f"   ✓ CA private key saved (TEST ONLY - secure in production!)")
    
    # Export CA certificate for receivers
    ca_cert = ca.export_ca_certificate()
    (test_dir / "ca_certificate.json").write_text(json.dumps(ca_cert, indent=2))
    print(f"   ✓ CA certificate exported for receivers")
    
    # Step 2: Generate sender key pair
    print("\n2️⃣  Generating sender key pair...")
    sender_private_key = Ed25519PrivateKey.generate()
    sender_public_key = sender_private_key.public_key()
    
    sender_fingerprint = _compute_fingerprint(sender_public_key)
    print(f"   ✓ Sender key generated")
    print(f"   ✓ Sender fingerprint: {sender_fingerprint}")
    
    # Save sender private key
    sender_private_pem = sender_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    (test_dir / "sender_private_key.pem").write_bytes(sender_private_pem)
    print(f"   ✓ Sender private key saved")
    
    # Step 3: Issue certificate to sender
    print("\n3️⃣  Issuing certificate to sender...")
    
    sender_identity = SenderIdentity(
        operator_name="Dr. Sarah Johnson",
        station_id="Medical-Scan-01",
        organization="City Hospital",
        department="IT Security",
        email="sjohnson@hospital.org",
        permissions=["medical_systems", "patient_records"]
    )
    
    cert = ca.issue_certificate(
        subject=sender_identity,
        public_key=sender_public_key,
        validity_days=365
    )
    
    print(f"   ✓ Certificate issued")
    print(f"   ✓ Serial: {cert.serial_number}")
    print(f"   ✓ Operator: {cert.subject.operator_name}")
    print(f"   ✓ Station: {cert.subject.station_id}")
    print(f"   ✓ Organization: {cert.subject.organization}")
    print(f"   ✓ Valid for: {cert.days_until_expiry()} days")
    
    # Save certificate
    cert.save(test_dir / "sender_certificate.json")
    print(f"   ✓ Certificate saved")
    
    # Step 4: Update shared_keys.py to use this key pair
    print("\n4️⃣  Updating test key configuration...")
    
    # Save key locations to a config file
    config = {
        "ca_certificate": str(test_dir / "ca_certificate.json"),
        "sender_certificate": str(test_dir / "sender_certificate.json"),
        "sender_private_key": str(test_dir / "sender_private_key.pem"),
        "instructions": [
            "Sender will load certificate from test_certificates/sender_certificate.json",
            "Receiver will load CA certificate from test_certificates/ca_certificate.json",
            "These paths are configured in the GUI code"
        ]
    }
    
    (test_dir / "config.json").write_text(json.dumps(config, indent=2))
    print(f"   ✓ Configuration saved")
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ Certificate Setup Complete!")
    print("\n📋 Next steps:")
    print("   1. Sender app will automatically load certificate from:")
    print(f"      {test_dir / 'sender_certificate.json'}")
    print("   2. Receiver app will automatically load CA certificate from:")
    print(f"      {test_dir / 'ca_certificate.json'}")
    print("   3. Run sender and receiver apps to test certificate verification")
    print("\n🧪 Test scenario:")
    print("   - Sender includes verified identity in manifest")
    print("   - Receiver verifies certificate and displays:")
    print(f"     👤 Operator: {sender_identity.operator_name}")
    print(f"     🏢 Organization: {sender_identity.organization}")
    print(f"     🖥️  Station: {sender_identity.station_id}")
    print("=" * 60)


def _compute_fingerprint(public_key) -> str:
    """Compute fingerprint of public key."""
    import hashlib
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_bytes).hexdigest()[:16]


if __name__ == "__main__":
    main()
