"""Shared key storage for testing - allows sender and receiver to trust each other."""

from __future__ import annotations

from pathlib import Path
from typing import Optional
import json
from airseal_common import KeyPair

# Keys directory for testing
KEYS_DIR = Path(__file__).parent / ".airseal_test_keys"
KEYS_DIR.mkdir(exist_ok=True)

SENDER_KEY_FILE = KEYS_DIR / "sender_key.json"
RECEIVER_KEY_FILE = KEYS_DIR / "receiver_key.json"


def get_or_create_sender_key(username: Optional[str] = None) -> KeyPair:
    """Get existing sender key or create new one.

    Prefers keys associated with the logged-in operator's certificate when available.
    """
    # Check for certificate-based key first
    candidate_key_paths: list[Path] = []

    if username:
        candidate_key_paths.append(Path(__file__).parent / "test_certificates" / username / f"{username}_private_key.pem")
        candidate_key_paths.append(Path("C:/ProgramData/AirSeal/certificates") / f"{username}_private_key.pem")

    candidate_key_paths.append(Path(__file__).parent / "test_certificates" / "sender_private_key.pem")
    candidate_key_paths.append(Path("C:/ProgramData/AirSeal/certificates") / "sender_private_key.pem")

    cert_key_path: Path | None = next((p for p in candidate_key_paths if p.exists()), None)

    if cert_key_path is not None:
        from cryptography.hazmat.primitives import serialization
        private_bytes = cert_key_path.read_bytes()
        private_key_obj = serialization.load_pem_private_key(private_bytes, password=None)
        key = KeyPair(private_key=private_key_obj)
        print(f"✓ Loaded sender key from certificate: {key.get_fingerprint()[:16]}... (source: {cert_key_path})")
        return key
    
    # Fall back to test key storage
    if SENDER_KEY_FILE.exists():
        with open(SENDER_KEY_FILE, 'r') as f:
            data = json.load(f)
            # Deserialize from stored hex strings
            from cryptography.hazmat.primitives import serialization
            
            private_bytes = bytes.fromhex(data['private_key'])
            private_key_obj = serialization.load_pem_private_key(private_bytes, password=None)
            
            # KeyPair constructor derives public key from private key
            key = KeyPair(private_key=private_key_obj)
            print(f"✓ Loaded sender key: {key.get_fingerprint()[:16]}...")
            return key
    
    # Create new key
    key = KeyPair.generate()
    
    # Serialize keys for storage
    from cryptography.hazmat.primitives import serialization
    private_bytes = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    with open(SENDER_KEY_FILE, 'w') as f:
        json.dump({
            'private_key': private_bytes.hex(),
            'public_key': public_bytes.hex(),
            'fingerprint': key.get_fingerprint()
        }, f, indent=2)
    
    print(f"✓ Created new sender key: {key.get_fingerprint()[:16]}...")
    return key


def get_or_create_receiver_key() -> KeyPair:
    """Get existing receiver key or create new one."""
    if RECEIVER_KEY_FILE.exists():
        with open(RECEIVER_KEY_FILE, 'r') as f:
            data = json.load(f)
            # Deserialize from stored hex strings
            from cryptography.hazmat.primitives import serialization
            
            private_bytes = bytes.fromhex(data['private_key'])
            private_key_obj = serialization.load_pem_private_key(private_bytes, password=None)
            
            # KeyPair constructor derives public key from private key
            key = KeyPair(private_key=private_key_obj)
            print(f"✓ Loaded receiver key: {key.get_fingerprint()[:16]}...")
            return key
    
    # Create new key
    key = KeyPair.generate()
    
    # Serialize keys for storage
    from cryptography.hazmat.primitives import serialization
    private_bytes = key.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    with open(RECEIVER_KEY_FILE, 'w') as f:
        json.dump({
            'private_key': private_bytes.hex(),
            'public_key': public_bytes.hex(),
            'fingerprint': key.get_fingerprint()
        }, f, indent=2)
    
    print(f"✓ Created new receiver key: {key.get_fingerprint()[:16]}...")
    return key


def reset_keys():
    """Delete all test keys - creates fresh keys on next run."""
    if SENDER_KEY_FILE.exists():
        SENDER_KEY_FILE.unlink()
        print("✓ Deleted sender key")
    
    if RECEIVER_KEY_FILE.exists():
        RECEIVER_KEY_FILE.unlink()
        print("✓ Deleted receiver key")
    
    print("✓ Keys reset - fresh keys will be created on next run")


if __name__ == "__main__":
    import sys
    
    print("\n=== AirSeal Test Key Manager ===\n")
    
    # Check if reset requested
    if "--reset" in sys.argv:
        print("=== Resetting Keys ===\n")
        reset_keys()
        print()
    
    sender = get_or_create_sender_key()
    receiver = get_or_create_receiver_key()
    
    print(f"\nSender fingerprint: {sender.get_fingerprint()}")
    print(f"Receiver fingerprint: {receiver.get_fingerprint()}")
    print(f"\nKeys stored in: {KEYS_DIR}")
    print("\nTo reset keys, run: python shared_keys.py --reset")
