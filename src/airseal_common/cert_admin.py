"""
AirSeal Certificate Management CLI

Admin tool for:
- Creating root CAs
- Issuing certificates to scanning stations
- Revoking certificates
- Generating CRLs for distribution
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

from airseal_common.certificates import (
    CertificateAuthority,
    SenderIdentity,
    Certificate,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import json


def create_root_ca(args):
    """Create a new root CA for the organization."""
    print(f"🏢 Creating Root CA: {args.name}")
    
    # Generate CA key pair
    ca_private_key = Ed25519PrivateKey.generate()
    ca_public_key = ca_private_key.public_key()
    
    # Create CA
    ca = CertificateAuthority(args.name, ca_private_key, ca_public_key)
    
    # Save CA private key (SECURE THIS!)
    ca_dir = Path(args.output) / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    
    private_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    (ca_dir / "ca_private_key.pem").write_bytes(private_pem)
    print(f"  ⚠️  Private key saved: {ca_dir / 'ca_private_key.pem'}")
    print(f"  ⚠️  SECURE THIS FILE! Store offline in vault!")
    
    # Export CA certificate for distribution
    ca_cert = ca.export_ca_certificate()
    (ca_dir / "ca_certificate.json").write_text(json.dumps(ca_cert, indent=2))
    print(f"  ✓ CA certificate saved: {ca_dir / 'ca_certificate.json'}")
    print(f"  ✓ Fingerprint: {ca.fingerprint}")
    print(f"\n📀 Distribute 'ca_certificate.json' to all receivers via CD/USB")


def issue_certificate(args):
    """Issue a certificate to a scanning station."""
    print(f"📜 Issuing Certificate")
    
    # Load CA
    ca_dir = Path(args.ca_dir)
    if not ca_dir.exists():
        print(f"❌ CA directory not found: {ca_dir}")
        sys.exit(1)
    
    # Load CA private key
    private_pem = (ca_dir / "ca_private_key.pem").read_bytes()
    ca_private_key = serialization.load_pem_private_key(private_pem, password=None)
    
    # Load CA cert to get name
    ca_cert = json.loads((ca_dir / "ca_certificate.json").read_text())
    ca_name = ca_cert["name"]
    
    ca_public_key = serialization.load_pem_public_key(ca_cert["public_key_pem"].encode())
    
    ca = CertificateAuthority(ca_name, ca_private_key, ca_public_key)

    stored_fp = ca_cert.get("fingerprint")
    if stored_fp and stored_fp != ca.fingerprint:
        print(
            f"❌ CA key / certificate mismatch (expected {stored_fp}, got {ca.fingerprint})."
        )
        sys.exit(1)
    
    # Load existing issued certs
    certs_dir = ca_dir / "issued_certificates"
    certs_dir.mkdir(exist_ok=True)
    
    # Create sender identity
    permissions = args.permissions.split(",") if args.permissions else []
    
    identity = SenderIdentity(
        operator_name=args.operator,
        station_id=args.station_id,
        organization=args.organization,
        department=args.department,
        email=args.email,
        permissions=permissions
    )
    
    # Load or generate sender key pair
    if args.sender_key:
        # Load existing key
        sender_pem = Path(args.sender_key).read_bytes()
        sender_private_key = serialization.load_pem_private_key(sender_pem, password=None)
        sender_public_key = sender_private_key.public_key()
        print(f"  ✓ Using existing sender key: {args.sender_key}")
    else:
        # Generate new key pair
        sender_private_key = Ed25519PrivateKey.generate()
        sender_public_key = sender_private_key.public_key()
        
        # Save sender private key
        sender_dir = ca_dir / "sender_keys" / args.station_id
        sender_dir.mkdir(parents=True, exist_ok=True)
        
        sender_pem = sender_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        (sender_dir / "private_key.pem").write_bytes(sender_pem)
        print(f"  ✓ Generated sender key: {sender_dir / 'private_key.pem'}")
    
    # Issue certificate
    cert = ca.issue_certificate(identity, sender_public_key, validity_days=args.validity_days)
    
    # Save certificate
    cert_file = certs_dir / f"{args.station_id}_{cert.serial_number}.json"
    cert.save(cert_file)
    
    print(f"\n✅ Certificate Issued Successfully!")
    print(f"  Serial: {cert.serial_number}")
    print(f"  Operator: {cert.subject.operator_name}")
    print(f"  Station: {cert.subject.station_id}")
    print(f"  Organization: {cert.subject.organization}")
    print(f"  Valid: {cert.get_validity_period()[0]} to {cert.get_validity_period()[1]}")
    print(f"  Certificate saved: {cert_file}")
    print(f"\n📋 Next steps:")
    print(f"  1. Give '{cert_file}' to sender station")
    print(f"  2. Sender includes this cert in manifests")
    print(f"  3. Receivers verify against CA cert")


def revoke_certificate(args):
    """Revoke a certificate and update CRL."""
    print(f"🚫 Revoking Certificate: {args.serial}")
    
    ca_dir = Path(args.ca_dir)
    certs_dir = ca_dir / "issued_certificates"
    
    # Find certificate
    cert_files = list(certs_dir.glob(f"*_{args.serial}.json"))
    if not cert_files:
        print(f"❌ Certificate not found: {args.serial}")
        sys.exit(1)
    
    cert_file = cert_files[0]
    cert = Certificate.load(cert_file)
    
    # Mark as revoked
    cert.revoked = True
    cert.revocation_reason = args.reason
    cert.save(cert_file)
    
    print(f"  ✓ Certificate revoked: {cert.subject.operator_name} ({cert.subject.station_id})")
    print(f"  Reason: {args.reason}")
    
    # Update CRL
    update_crl(ca_dir)


def update_crl(ca_dir: Path):
    """Update Certificate Revocation List."""
    print(f"\n📋 Updating CRL...")
    
    certs_dir = ca_dir / "issued_certificates"
    crl_file = ca_dir / "crl.json"
    
    # Collect revoked certificates
    revoked_serials = []
    for cert_file in certs_dir.glob("*.json"):
        cert = Certificate.load(cert_file)
        if cert.revoked:
            revoked_serials.append({
                "serial": cert.serial_number,
                "reason": cert.revocation_reason,
                "station_id": cert.subject.station_id,
                "operator": cert.subject.operator_name,
            })
    
    # Save CRL
    crl = {
        "version": "1.0",
        "updated_at": datetime.now().isoformat(),
        "revoked_count": len(revoked_serials),
        "revoked_serials": [r["serial"] for r in revoked_serials],
        "revoked_details": revoked_serials,
    }
    
    crl_file.write_text(json.dumps(crl, indent=2))
    print(f"  ✓ CRL updated: {crl_file}")
    print(f"  ✓ Revoked certificates: {len(revoked_serials)}")
    print(f"\n📀 Distribute 'crl.json' to all receivers via CD/USB")


def list_certificates(args):
    """List all issued certificates."""
    ca_dir = Path(args.ca_dir)
    certs_dir = ca_dir / "issued_certificates"
    
    if not certs_dir.exists():
        print("No certificates issued yet.")
        return
    
    print("📜 Issued Certificates:")
    print()
    
    for cert_file in sorted(certs_dir.glob("*.json")):
        cert = Certificate.load(cert_file)
        status = "🚫 REVOKED" if cert.revoked else ("✅ Valid" if cert.is_valid_at()[0] else "⏰ Expired")
        
        print(f"{status} {cert.subject.station_id} - {cert.subject.operator_name}")
        print(f"   Serial: {cert.serial_number}")
        print(f"   Organization: {cert.subject.organization}")
        print(f"   Valid: {cert.get_validity_period()[0].date()} to {cert.get_validity_period()[1].date()}")
        print(f"   Days left: {cert.days_until_expiry()}")
        if cert.revoked:
            print(f"   Revocation reason: {cert.revocation_reason}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="AirSeal Certificate Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create root CA
  python -m airseal_common.cert_admin create-ca --name "City Hospital Root CA" --output ./certificates

  # Issue certificate to scanning station
  python -m airseal_common.cert_admin issue \\
      --ca-dir ./certificates/ca \\
      --operator "Dr. Sarah Johnson" \\
      --station-id "Medical-Scan-01" \\
      --organization "City Hospital" \\
      --department "IT Security" \\
      --email "sjohnson@hospital.org" \\
      --permissions "medical_systems,patient_records" \\
      --validity-days 365

  # Revoke certificate
  python -m airsael_common.cert_admin revoke \\
      --ca-dir ./certificates/ca \\
      --serial abc123def456 \\
      --reason "Station compromised"

  # List all certificates
  python -m airseal_common.cert_admin list --ca-dir ./certificates/ca
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # create-ca command
    ca_parser = subparsers.add_parser('create-ca', help='Create root CA')
    ca_parser.add_argument('--name', required=True, help='CA name (e.g., "City Hospital Root CA")')
    ca_parser.add_argument('--output', default='./certificates', help='Output directory')
    
    # issue command
    issue_parser = subparsers.add_parser('issue', help='Issue certificate')
    issue_parser.add_argument('--ca-dir', required=True, help='CA directory')
    issue_parser.add_argument('--operator', required=True, help='Operator name')
    issue_parser.add_argument('--station-id', required=True, help='Station ID')
    issue_parser.add_argument('--organization', required=True, help='Organization name')
    issue_parser.add_argument('--department', required=True, help='Department')
    issue_parser.add_argument('--email', help='Email address')
    issue_parser.add_argument('--permissions', help='Comma-separated permissions')
    issue_parser.add_argument('--validity-days', type=int, default=365, help='Validity period in days')
    issue_parser.add_argument('--sender-key', help='Existing sender private key (optional)')
    
    # revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke certificate')
    revoke_parser.add_argument('--ca-dir', required=True, help='CA directory')
    revoke_parser.add_argument('--serial', required=True, help='Certificate serial number')
    revoke_parser.add_argument('--reason', required=True, help='Revocation reason')
    
    # list command
    list_parser = subparsers.add_parser('list', help='List certificates')
    list_parser.add_argument('--ca-dir', required=True, help='CA directory')
    
    args = parser.parse_args()
    
    if args.command == 'create-ca':
        create_root_ca(args)
    elif args.command == 'issue':
        issue_certificate(args)
    elif args.command == 'revoke':
        revoke_certificate(args)
    elif args.command == 'list':
        list_certificates(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
