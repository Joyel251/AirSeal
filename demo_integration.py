"""
AirSeal Integration Demo - Backend + Frontend Test
This script demonstrates the integrated cryptographic backend working with GUI components.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common import (
    KeyPair,
    TrustStore,
    NonceManager,
    Manifest,
    ManifestSigner,
    ManifestVerifier,
    PolicyStore,
    QRCodeGenerator,
    ManifestQRData,
    compute_file_hash,
    ScannerFactory,
    ImportReceipt,
    ReceiptSigner,
    DEFAULT_POLICY,
)
import tempfile
import time
import json
from dataclasses import asdict

print("=" * 70)
print("AirSeal Backend + Frontend Integration Demo")
print("=" * 70)

# Step 1: Setup (simulating what GUIs do on launch)
print("\n[1] Setting up cryptographic components...")
sender_key = KeyPair.generate()
receiver_key = KeyPair.generate()
trust_store = TrustStore()
nonce_mgr = NonceManager()

# Initialize PolicyStore with skip_disk=True for demo
policy_store = PolicyStore(skip_disk=True)
print(f"✓ Default policies loaded: {', '.join(policy_store.list_policies())}")

# Receiver adds sender's key to trust store
trust_store.add_key(
    key_id=sender_key.get_fingerprint(),
    public_key=sender_key.public_key
)

print(f"✓ Sender key fingerprint: {sender_key.get_fingerprint()[:16]}...")
print(f"✓ Receiver key fingerprint: {receiver_key.get_fingerprint()[:16]}...")
print(f"✓ Sender key added to receiver's trust store")

# Step 2: Receiver generates nonce (NonceGenerator worker)
print("\n[2] Receiver: Generating nonce...")
nonce_data = nonce_mgr.generate_nonce()
print(f"✓ Nonce: {nonce_data.nonce[:16]}...")
print(f"✓ Transfer ID: {nonce_data.transfer_id}")

# Generate nonce QR (what receiver GUI displays)
from airseal_common import NonceQRData
nonce_qr_data = NonceQRData(
    transfer_id=nonce_data.transfer_id,
    nonce=nonce_data.nonce,
    timestamp=time.time()
)
qr_gen = QRCodeGenerator()
nonce_qr_img = qr_gen.generate(nonce_qr_data.to_json())
print(f"✓ Nonce QR generated: {nonce_qr_img.size} pixels")

# Step 3: Sender scans file (ScanWorker)
print("\n[3] Sender: Scanning test file...")

# Create a test file
with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
    test_file = Path(f.name)
    f.write("This is a test file for AirSeal demo.\n")
    f.write("It demonstrates the integrated backend working!\n")

print(f"✓ Test file created: {test_file.name}")

# Compute hash
file_hash = compute_file_hash(test_file)
print(f"✓ File hash: {file_hash[:32]}...")

# Scan for malware
scanner = ScannerFactory.get_scanner()
scan_result = scanner.scan(test_file)
print(f"✓ Malware scan: {scan_result.status} ({scan_result.engine})")

# Create manifest with CORRECT policy_id
manifest = Manifest(
    filename=test_file.name,
    size=test_file.stat().st_size,
    sha256=file_hash,
    scan_status=scan_result.status,
    scan_engine=scan_result.engine,
    scan_details=scan_result.details,
    timestamp=time.time(),
    signer_id=sender_key.get_fingerprint(),
    policy_id=DEFAULT_POLICY.policy_id,  # ✅ Use DEFAULT_POLICY.policy_id
    nonce=nonce_data.nonce,
    transfer_id=nonce_data.transfer_id,
)

print(f"✓ Manifest created: {manifest.filename}, {manifest.size} bytes")
print(f"✓ Policy ID: {manifest.policy_id}")

# Sign manifest
signer = ManifestSigner(sender_key)
signed_manifest = signer.sign_manifest(manifest)
print(f"✓ Manifest signed with sender's key")
print(f"  Signature: {signed_manifest.signature[:32]}...")

# Generate manifest QR (what sender GUI displays)
manifest_dict = asdict(signed_manifest)
manifest_json = json.dumps(manifest_dict)
manifest_qr = ManifestQRData(manifest_json=manifest_json)
manifest_qr_img = qr_gen.generate(manifest_qr.to_json())
print(f"✓ Manifest QR generated: {manifest_qr_img.size} pixels")

# Step 4: Receiver scans manifest QR (ManifestScanner worker)
print("\n[4] Receiver: Verifying manifest from QR...")

# Simulate QR parsing (in real GUI, this comes from camera or file)
manifest_json = manifest_qr.to_json()
parsed_qr = ManifestQRData.from_json(manifest_json)
parsed_manifest = Manifest(**parsed_qr.get_manifest_dict())

print(f"✓ QR decoded and parsed")

# Verify signature
verifier = ManifestVerifier(trust_store, nonce_mgr)
success, error = verifier.verify_manifest(parsed_manifest)
if success:
    print(f"✓ Signature verification: PASSED")
else:
    print(f"✗ Signature verification: FAILED - {error}")
    sys.exit(1)

# Check policy
print(f"✓ Checking policy: {parsed_manifest.policy_id}...")

if not policy_store.has_policy(parsed_manifest.policy_id):
    print(f"✗ Policy not found: {parsed_manifest.policy_id}")
    print(f"  Available policies: {', '.join(policy_store.list_policies())}")
    sys.exit(1)

engine = policy_store.get_engine(parsed_manifest.policy_id)

if not engine:
    print(f"✗ Could not create policy engine for: {parsed_manifest.policy_id}")
    sys.exit(1)

complies, reason = engine.check_manifest(parsed_manifest)
if complies:
    print(f"✓ Policy check: PASSED")
    print(f"  {reason}")
else:
    print(f"✗ Policy check: FAILED")
    print(f"  {reason}")
    sys.exit(1)

# Step 5: Receiver verifies actual file (FileVerifier worker)
print("\n[5] Receiver: Verifying actual file...")

# Compute hash of file
actual_hash = compute_file_hash(test_file)
print(f"✓ File hash computed: {actual_hash[:32]}...")

# Compare hashes
if actual_hash == parsed_manifest.sha256:
    print(f"✓ Hash verification: MATCH")
else:
    print(f"✗ Hash verification: MISMATCH")
    print(f"  Expected: {parsed_manifest.sha256}")
    print(f"  Actual:   {actual_hash}")
    sys.exit(1)

# Check file policy
safe, reason = engine.check_file(test_file)
if safe:
    print(f"✓ File policy check: PASSED")
    print(f"  {reason}")
else:
    print(f"✗ File policy check: FAILED")
    print(f"  {reason}")
    sys.exit(1)

# Generate import receipt
print("\n[6] Generating import receipt...")
receipt = ImportReceipt(
    result="SUCCESS",
    sha256=actual_hash,
    filename=parsed_manifest.filename,
    timestamp=time.time(),
    transfer_id=parsed_manifest.transfer_id,
    verifier_id=receiver_key.get_fingerprint(),
    reason="File verified and imported successfully"
)

receipt_signer = ReceiptSigner(receiver_key)
signed_receipt = receipt_signer.sign_receipt(receipt)
receipt_path = receipt_signer.save_receipt(signed_receipt)

print(f"✓ Import receipt generated")
print(f"✓ Receipt saved: {receipt_path.name}")
print(f"  Verifier: {receipt.verifier_id[:16]}...")

# Cleanup
test_file.unlink()
print(f"✓ Test file cleaned up")

print("\n" + "=" * 70)
print("✅ Demo Complete! All integration points working:")
print("  ✓ Key generation and trust store")
print("  ✓ Nonce generation and QR encoding")
print("  ✓ File scanning and hashing")
print("  ✓ Manifest signing and QR encoding")
print("  ✓ QR parsing and manifest verification")
print("  ✓ Signature verification with trust store")
print("  ✓ Policy enforcement")
print("  ✓ File hash verification")
print("  ✓ Receipt generation and signing")
print("=" * 70)
print("\n🎉 Backend and Frontend are fully integrated!")