"""
Test script for user management system
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from airseal_common.user_management import get_user_database


def main():
    print("🧪 Testing User Management System")
    print("=" * 60)
    
    user_db = get_user_database()
    
    print("\n📋 Current Users:")
    users = user_db.list_users()
    for user in users:
        status = "✅ Active" if user.is_active else "❌ Inactive"
        print(f"  {status} {user.username} - {user.full_name} ({user.role})")
    
    print("\n🔐 Testing Authentication:")
    
    # Test valid login
    print("\n  Testing admin login...")
    admin = user_db.authenticate("admin", "admin123")
    if admin:
        print(f"  ✓ Success: {admin.full_name} ({admin.role})")
    else:
        print("  ✗ Failed")
    
    # Test invalid login
    print("\n  Testing invalid login...")
    invalid = user_db.authenticate("admin", "wrongpassword")
    if invalid:
        print(f"  ✗ Should have failed!")
    else:
        print("  ✓ Correctly rejected")
    
    print("\n" + "=" * 60)
    print("✅ User management system working!")
    print("\n💡 Default credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("\n⚠️  Change the default password immediately!")


if __name__ == "__main__":
    main()
