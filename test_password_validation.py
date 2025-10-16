"""
Test password validation and security features.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common.user_management import UserDatabase, validate_password_strength


def test_password_validation():
    """Test password strength validation."""
    print("=" * 60)
    print("PASSWORD VALIDATION TESTS")
    print("=" * 60)
    
    test_cases = [
        ("weak", False, "Too short"),
        ("WeakPass1!", True, "Valid but only 11 chars"),
        ("StrongP@ss123", True, "Valid 13 chars"),
        ("UPPERCASE123!", False, "Missing lowercase"),
        ("lowercase123!", False, "Missing uppercase"),
        ("NoDigitsHere!", False, "Missing digit"),
        ("NoSpecial123", False, "Missing special char"),
        ("password", False, "Common word"),
        ("admin123", False, "Common word"),
        ("SecureP@ssw0rd2024", True, "Strong password"),
    ]
    
    for password, expected_valid, description in test_cases:
        is_valid, msg = validate_password_strength(password)
        status = "✓ PASS" if is_valid == expected_valid else "✗ FAIL"
        print(f"\n{status}: {description}")
        print(f"  Password: '{password}'")
        print(f"  Result: {'Valid' if is_valid else 'Invalid'} - {msg}")


def test_account_lockout():
    """Test account lockout after failed attempts."""
    print("\n" + "=" * 60)
    print("ACCOUNT LOCKOUT TEST")
    print("=" * 60)
    
    # Create test database
    test_db_path = Path("test_lockout_db")
    if test_db_path.exists():
        import shutil
        shutil.rmtree(test_db_path)
    
    db = UserDatabase(test_db_path)
    
    # Create test user
    print("\nCreating test user...")
    db.create_user(
        username="testuser",
        password="TestP@ssw0rd123",
        role="operator",
        full_name="Test User",
        skip_password_validation=True
    )
    print("✓ User created")
    
    # Attempt login with wrong password 5 times
    print("\nAttempting 5 failed logins...")
    for i in range(5):
        result = db.authenticate("testuser", "wrongpassword")
        print(f"  Attempt {i+1}: {result}")
    
    # Check if account is locked
    user = db.get_user("testuser")
    print(f"\nAccount status:")
    print(f"  Failed attempts: {user.failed_login_attempts}")
    print(f"  Locked: {user.locked_until is not None}")
    
    # Try to login with correct password (should fail due to lock)
    print("\nAttempting login with correct password...")
    result = db.authenticate("testuser", "TestP@ssw0rd123")
    if result is None:
        print("✓ Account locked successfully - login denied")
    else:
        print("✗ FAIL - Should be locked")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_db_path)
    print("\n✓ Test database cleaned up")


def test_secure_admin_password():
    """Test that default admin gets secure random password."""
    print("\n" + "=" * 60)
    print("SECURE ADMIN PASSWORD TEST")
    print("=" * 60)
    
    # Create test database
    test_db_path = Path("test_admin_db")
    if test_db_path.exists():
        import shutil
        shutil.rmtree(test_db_path)
    
    print("\nCreating new database with default admin...")
    db = UserDatabase(test_db_path)
    
    # Check if password file was created
    pwd_file = test_db_path / ".admin_initial_password.txt"
    if pwd_file.exists():
        print("✓ Temporary password file created")
        content = pwd_file.read_text()
        print(f"\nPassword file content preview:")
        print(content[:100] + "...")
        
        # Verify password is random (not "admin123")
        if "admin123" not in content:
            print("\n✓ Password is NOT 'admin123' (secure)")
        else:
            print("\n✗ FAIL - Still using admin123")
    else:
        print("✗ Password file not found")
    
    # Cleanup
    import shutil
    shutil.rmtree(test_db_path)
    print("\n✓ Test database cleaned up")


if __name__ == "__main__":
    try:
        test_password_validation()
        test_account_lockout()
        test_secure_admin_password()
        
        print("\n" + "=" * 60)
        print("ALL TESTS COMPLETED")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
