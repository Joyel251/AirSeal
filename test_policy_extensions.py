"""Test policy extensions - verify .mp4 and other file types are allowed."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common.policy import PolicyStore, PolicyEngine

def test_policy_extensions():
    """Test that common file extensions are allowed in DEFAULT_POLICY."""
    
    print("="*70)
    print("TESTING AIRSEAL FILE EXTENSION POLICY")
    print("="*70)
    
    # Create policy store
    store = PolicyStore(skip_disk=True)
    policy = store.get_policy("default-v1")
    
    print(f"\nPolicy: {policy.name}")
    print(f"Policy ID: {policy.policy_id}")
    print(f"Total allowed extensions: {len(policy.allowed_extensions)}")
    print(f"Max file size: {policy.max_file_size_mb} MB")
    print()
    
    # Test common file extensions
    test_files = [
        # Videos
        ("video.mp4", "MP4 Video"),
        ("movie.avi", "AVI Video"),
        ("film.mkv", "MKV Video"),
        ("clip.mov", "MOV Video"),
        
        # Executables
        ("setup.exe", "Windows Executable"),
        ("installer.msi", "Windows Installer"),
        ("app.apk", "Android App"),
        
        # Archives
        ("backup.zip", "ZIP Archive"),
        ("data.rar", "RAR Archive"),
        ("files.7z", "7-Zip Archive"),
        
        # Documents
        ("report.pdf", "PDF Document"),
        ("document.docx", "Word Document"),
        
        # Images
        ("photo.jpg", "JPEG Image"),
        ("picture.png", "PNG Image"),
        
        # Audio
        ("song.mp3", "MP3 Audio"),
        ("track.flac", "FLAC Audio"),
    ]
    
    print("Testing file extensions:")
    print("-" * 70)
    
    passed = 0
    failed = 0
    
    for filename, description in test_files:
        ext = Path(filename).suffix
        
        # Check if extension is in allowed list
        if ext in policy.allowed_extensions:
            status = "✅ ALLOWED"
            passed += 1
        else:
            status = "❌ BLOCKED"
            failed += 1
        
        print(f"{status:12} | {filename:20} | {description}")
    
    print("-" * 70)
    print(f"\nResults: {passed} passed, {failed} failed")
    
    if failed > 0:
        print("\n⚠️  WARNING: Some extensions are not allowed!")
        print("This means the policy is not loaded correctly.")
    else:
        print("\n✅ SUCCESS: All test files are allowed by the policy!")
    
    print("\n" + "="*70)
    
    return failed == 0

if __name__ == "__main__":
    success = test_policy_extensions()
    sys.exit(0 if success else 1)
