"""Regenerate policy files on disk with updated extensions."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common.policy import PolicyStore, DEFAULT_POLICY, HIGH_SECURITY_POLICY, PERMISSIVE_POLICY

def regenerate_policies():
    """Regenerate all policy files on disk."""
    
    print("="*70)
    print("REGENERATING POLICY FILES")
    print("="*70)
    print()
    
    # Create policy store (will access disk)
    store = PolicyStore()
    
    print(f"Policy store location: {store.store_path}")
    print()
    
    # Save all policies
    policies = [
        ("DEFAULT_POLICY", DEFAULT_POLICY),
        ("HIGH_SECURITY_POLICY", HIGH_SECURITY_POLICY),
        ("PERMISSIVE_POLICY", PERMISSIVE_POLICY),
    ]
    
    for name, policy in policies:
        print(f"Saving {name}...")
        print(f"  Policy ID: {policy.policy_id}")
        print(f"  Name: {policy.name}")
        print(f"  Allowed extensions: {len(policy.allowed_extensions)}")
        print(f"  Max file size: {policy.max_file_size_mb} MB")
        
        # Save to disk
        store.add_policy(policy, save=True)
        
        # Verify
        policy_file = store.store_path / f"{policy.policy_id}.json"
        if policy_file.exists():
            print(f"  ✅ Saved to: {policy_file}")
        else:
            print(f"  ❌ Failed to save!")
        print()
    
    print("="*70)
    print("✅ POLICY FILES REGENERATED")
    print("="*70)
    print()
    print("Next steps:")
    print("1. Restart sender: python -m airseal_sender.gui")
    print("2. Restart receiver: python -m airseal_receiver.gui")
    print("3. Try transferring .mp4, .exe, or any of the 94 supported file types")
    print()

if __name__ == "__main__":
    regenerate_policies()
