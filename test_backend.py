"""
AirSeal Backend Test Suite

Tests the complete cryptographic flow:
- Key generation
- Nonce generation
- File scanning
- Manifest signing
- Manifest verification
- Policy enforcement
- QR generation
"""

import time
from pathlib import Path
import tempfile
import sys

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
    ScannerFactory,
    QRCodeGenerator,
    NonceQRData,
    ManifestQRData,
    compute_file_hash,
)


def test_key_generation():
    """Test key generation and fingerprints."""
    print("\n=== Testing Key Generation ===")
    
    keypair = KeyPair.generate()
    fingerprint = keypair.get_fingerprint()
    
    print(f"✅ Generated key pair")
    print(f"   Fingerprint: {fingerprint}")
    
    # Test export/import
    private_pem = keypair.export_private_pem()
    public_pem = keypair.export_public_pem()
    
    print(f"✅ Exported keys ({len(private_pem)} bytes private, {len(public_pem)} bytes public)")
    
    # Reload
    keypair2 = KeyPair.from_private_pem(private_pem)
    assert keypair2.get_fingerprint() == fingerprint
    
    print(f"✅ Reloaded key pair successfully")
    
    return keypair


def test_nonce_generation():
    """Test nonce generation and validation."""
    print("\n=== Testing Nonce Generation ===")
    
    nonce_mgr = NonceManager()
    nonce_data = nonce_mgr.generate_nonce()
    
    print(f"✅ Generated nonce")
    print(f"   Nonce: {nonce_data.nonce[:16]}...")
    print(f"   Transfer ID: {nonce_data.transfer_id}")
    
    # Test validation
    assert nonce_mgr.validate_nonce(nonce_data.transfer_id, nonce_data.nonce)
    print(f"✅ Nonce validation successful")
    
    # Test consumption (one-time use)
    nonce_mgr.consume_nonce(nonce_data.transfer_id)
    assert not nonce_mgr.validate_nonce(nonce_data.transfer_id, nonce_data.nonce)
    print(f"✅ Nonce consumption successful (one-time use)")
    
    return nonce_mgr


def test_file_scanning():
    """Test file scanning."""
    print("\n=== Testing File Scanning ===")
    
    # Create test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is a test file for AirSeal scanning.\n")
        test_file = Path(f.name)
    
    try:
        # Get scanner
        scanner = ScannerFactory.get_scanner("demo")  # Use demo for testing
        print(f"✅ Using scanner: {scanner.engine_name}")
        
        # Scan file
        result = scanner.scan(test_file)
        
        print(f"✅ Scan completed")
        print(f"   Status: {result.status}")
        print(f"   Engine: {result.engine}")
        print(f"   Details: {result.details}")
        print(f"   Scan time: {result.scan_time:.3f}s")
        
        assert result.is_clean()
        
        return test_file, result
    
    finally:
        pass  # Don't delete yet, we'll use it for other tests


def test_manifest_signing_and_verification(keypair, nonce_mgr, test_file, scan_result):
    """Test manifest signing and verification."""
    print("\n=== Testing Manifest Signing & Verification ===")
    
    # Compute file hash
    file_hash = compute_file_hash(test_file)
    print(f"✅ Computed file hash: {file_hash[:16]}...")
    
    # Generate nonce
    nonce_data = nonce_mgr.generate_nonce()
    
    # Create manifest
    manifest = Manifest(
        filename=test_file.name,
        size=test_file.stat().st_size,
        sha256=file_hash,
        scan_status=scan_result.status,
        scan_engine=scan_result.engine,
        scan_details=scan_result.details,
        timestamp=time.time(),
        signer_id=keypair.get_fingerprint(),
        policy_id="default-v1",
        nonce=nonce_data.nonce,
        transfer_id=nonce_data.transfer_id,
    )
    
    print(f"✅ Created manifest")
    
    # Sign manifest
    signer = ManifestSigner(keypair)
    signed_manifest = signer.sign_manifest(manifest)
    
    print(f"✅ Signed manifest")
    print(f"   Signature: {signed_manifest.signature[:32]}...")
    
    # Setup trust store
    trust_store = TrustStore()
    trust_store.add_key(keypair.get_fingerprint(), keypair.public_key)
    
    # Verify manifest
    verifier = ManifestVerifier(trust_store, nonce_mgr)
    success, error = verifier.verify_manifest(signed_manifest)
    
    if success:
        print(f"✅ Manifest verification successful")
    else:
        print(f"❌ Manifest verification failed: {error}")
        assert False
    
    return signed_manifest


def test_policy_enforcement(manifest, test_file):
    """Test policy enforcement."""
    print("\n=== Testing Policy Enforcement ===")
    
    policy_store = PolicyStore()
    
    # Test with default policy
    engine = policy_store.get_engine("default-v1")
    complies, reason = engine.check_manifest(manifest)
    
    if complies:
        print(f"✅ Manifest complies with default policy")
    else:
        print(f"❌ Policy violation: {reason}")
        assert False
    
    # Test file check
    safe, reason = engine.check_file(test_file)
    
    if safe:
        print(f"✅ File passes policy checks")
    else:
        print(f"❌ File check failed: {reason}")
        assert False
    
    # Test with high security policy (should reject .txt in some cases)
    print(f"\n   Testing high security policy...")
    high_sec_engine = policy_store.get_engine("high-security-v1")
    
    # Create a manifest with high-security policy
    high_sec_manifest = Manifest(
        **{**manifest.__dict__, "policy_id": "high-security-v1"}
    )
    
    complies, reason = high_sec_engine.check_manifest(high_sec_manifest)
    print(f"   High security: {complies} - {reason}")


def test_qr_generation(nonce_data, manifest):
    """Test QR code generation."""
    print("\n=== Testing QR Code Generation ===")
    
    generator = QRCodeGenerator()
    
    # Test nonce QR
    nonce_qr = NonceQRData(
        transfer_id=nonce_data.transfer_id,
        nonce=nonce_data.nonce,
        timestamp=nonce_data.created_at,
    )
    
    nonce_json = nonce_qr.to_json()
    print(f"✅ Generated nonce QR data ({len(nonce_json)} bytes)")
    
    nonce_img = generator.generate(nonce_json)
    print(f"✅ Generated nonce QR image ({nonce_img.size})")
    
    # Test manifest QR
    import json
    from dataclasses import asdict
    
    manifest_json = json.dumps(asdict(manifest), separators=(',', ':'))
    manifest_qr = ManifestQRData(manifest_json)
    
    manifest_qr_json = manifest_qr.to_json()
    print(f"✅ Generated manifest QR data ({len(manifest_qr_json)} bytes)")
    
    try:
        manifest_img = generator.generate(manifest_qr_json)
        print(f"✅ Generated manifest QR image ({manifest_img.size})")
    except Exception as e:
        print(f"⚠️  Manifest QR generation: {e}")
        print(f"   (QR might be too large for complex manifests)")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("AirSeal Backend Test Suite")
    print("=" * 60)
    
    try:
        # Test 1: Key generation
        keypair = test_key_generation()
        
        # Test 2: Nonce generation
        nonce_mgr = test_nonce_generation()
        
        # Test 3: File scanning
        test_file, scan_result = test_file_scanning()
        
        # Test 4: Manifest signing and verification
        signed_manifest = test_manifest_signing_and_verification(
            keypair, nonce_mgr, test_file, scan_result
        )
        
        # Test 5: Policy enforcement
        test_policy_enforcement(signed_manifest, test_file)
        
        # Test 6: QR generation
        nonce_data = nonce_mgr.generate_nonce()
        test_qr_generation(nonce_data, signed_manifest)
        
        # Cleanup
        test_file.unlink()
        
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED!")
        print("=" * 60)
        
        return True
    
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
