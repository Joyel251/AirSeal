"""
AirSeal User Management System

Handles:
- User authentication
- Role-based access control
- User database management
- Password hashing and verification
"""

from __future__ import annotations

import json
import hashlib
import secrets
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List
from datetime import datetime


@dataclass
class User:
    """User account information."""
    username: str
    password_hash: str  # SHA-256 hash of password (10000 iterations)
    salt: str  # Random salt for password hashing (32 bytes)
    role: str  # "admin", "operator", "viewer"
    full_name: str
    email: Optional[str] = None
    station_id: Optional[str] = None
    organization: str = ""
    department: str = ""
    created_at: float = None
    last_login: Optional[float] = None
    last_activity: Optional[float] = None
    failed_login_attempts: int = 0
    locked_until: Optional[float] = None
    is_active: bool = True
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().timestamp()
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> User:
        """Create from dictionary."""
        return cls(**data)
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        computed_hash = _hash_password(password, self.salt)
        return computed_hash == self.password_hash
    
    def update_last_login(self):
        """Update last login timestamp."""
        self.last_login = datetime.now().timestamp()


def _hash_password(password: str, salt: str) -> str:
    """Hash password with salt using SHA-256 with multiple iterations."""
    salted = f"{salt}{password}{salt}".encode('utf-8')
    # Multiple iterations for added security
    result = salted
    for _ in range(10000):
        result = hashlib.sha256(result).digest()
    return result.hex()


def _generate_salt() -> str:
    """Generate random salt for password hashing."""
    return secrets.token_hex(32)  # Increased from 16 to 32 bytes


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements.
    
    Returns:
        (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak passwords
    weak_passwords = ["password", "12345678", "qwerty", "admin", "letmein"]
    if password.lower() in weak_passwords or any(weak in password.lower() for weak in weak_passwords):
        return False, "Password is too common or weak"
    
    return True, "Password meets requirements"


class UserDatabase:
    """User database manager."""
    
    def __init__(self, db_path: Optional[Path] = None):
        """Initialize user database."""
        if db_path is None:
            # Default location
            db_path = Path("C:/ProgramData/AirSeal/users")
        
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        self.users_file = self.db_path / "users.json"
        self.users: Dict[str, User] = {}
        
        # Load existing users or create default admin
        if self.users_file.exists():
            self._load_users()
        else:
            self._create_default_admin()
    
    def _load_users(self):
        """Load users from file."""
        try:
            data = json.loads(self.users_file.read_text())
            for username, user_data in data.items():
                self.users[username] = User.from_dict(user_data)
            print(f"✓ Loaded {len(self.users)} users from database")
        except Exception as e:
            print(f"⚠ Error loading users: {e}")
            self._create_default_admin()
    
    def _save_users(self):
        """Save users to file."""
        try:
            data = {username: user.to_dict() for username, user in self.users.items()}
            self.users_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            print(f"❌ Error saving users: {e}")
            raise
    
    def _create_default_admin(self):
        """Create default admin account with secure random password."""
        print("Creating default admin account...")
        
        # Generate secure random password
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        temp_password = ''.join(secrets.choice(chars) for _ in range(16))
        
        # Create admin with random password (skip validation for system-generated password)
        admin_user = self.create_user(
            username="admin",
            password=temp_password,
            role="admin",
            full_name="System Administrator",
            organization="AirSeal",
            department="IT Security",
            skip_password_validation=True
        )
        
        # Save temporary password to secure file
        pwd_file = self.db_path / ".admin_initial_password.txt"
        pwd_file.write_text(f"Username: admin\nTemporary Password: {temp_password}\n\nCHANGE THIS PASSWORD ON FIRST LOGIN!")
        
        print(f"Default admin created: {admin_user.username}")
        print(f"IMPORTANT: Temporary password saved to: {pwd_file}")
        print(f"You MUST change this password on first login!")
        print(f"Delete the password file after first login.")
    
    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        full_name: str,
        email: Optional[str] = None,
        station_id: Optional[str] = None,
        organization: str = "",
        department: str = "",
        skip_password_validation: bool = False
    ) -> User:
        """Create new user account with password strength validation."""
        if username in self.users:
            raise ValueError(f"User '{username}' already exists")
        
        if role not in ["admin", "operator", "viewer"]:
            raise ValueError(f"Invalid role: {role}")
        
        # Validate password strength (unless skipped for system-generated passwords)
        if not skip_password_validation:
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                raise ValueError(f"Weak password: {error_msg}")
        
        # Generate salt and hash password
        salt = _generate_salt()
        password_hash = _hash_password(password, salt)
        
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            role=role,
            full_name=full_name,
            email=email,
            station_id=station_id,
            organization=organization,
            department=department
        )
        
        self.users[username] = user
        self._save_users()
        
        print(f"✓ Created user: {username} ({role})")
        return user
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """
        Authenticate user with username and password.
        Implements account lockout after 5 failed attempts.
        """
        user = self.users.get(username)
        
        if not user:
            return None
        
        if not user.is_active:
            return None
        
        # Check if account is locked
        if user.locked_until and time.time() < user.locked_until:
            remaining = int((user.locked_until - time.time()) / 60)
            print(f"Account locked. Try again in {remaining} minutes.")
            return None
        
        # Clear lockout if expired
        if user.locked_until and time.time() >= user.locked_until:
            user.locked_until = None
            user.failed_login_attempts = 0
        
        # Verify password
        if not user.verify_password(password):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts (30 minutes lockout)
            if user.failed_login_attempts >= 5:
                user.locked_until = time.time() + (30 * 60)  # 30 minutes
                print(f"Account locked due to too many failed attempts. Locked for 30 minutes.")
            
            self._save_users()
            return None
        
        # Successful login - reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.update_last_login()
        self._save_users()
        
        return user
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        user = self.users.get(username)
        
        if not user:
            return False
        
        if not user.verify_password(old_password):
            return False
        
        # Generate new salt and hash
        user.salt = _generate_salt()
        user.password_hash = _hash_password(new_password, user.salt)
        
        self._save_users()
        print(f"✓ Password changed for user: {username}")
        return True
    
    def reset_password(self, username: str, new_password: str, admin_user: User) -> bool:
        """Admin can reset user password."""
        if admin_user.role != "admin":
            raise PermissionError("Only admins can reset passwords")
        
        user = self.users.get(username)
        if not user:
            return False
        
        # Generate new salt and hash
        user.salt = _generate_salt()
        user.password_hash = _hash_password(new_password, user.salt)
        
        self._save_users()
        print(f"✓ Password reset for user: {username}")
        return True
    
    def delete_user(self, username: str, admin_user: User) -> bool:
        """Delete user account (admin only)."""
        if admin_user.role != "admin":
            raise PermissionError("Only admins can delete users")
        
        if username == "admin":
            raise ValueError("Cannot delete default admin account")
        
        if username in self.users:
            del self.users[username]
            self._save_users()
            print(f"✓ Deleted user: {username}")
            return True
        
        return False
    
    def deactivate_user(self, username: str, admin_user: User) -> bool:
        """Deactivate user account (admin only)."""
        if admin_user.role != "admin":
            raise PermissionError("Only admins can deactivate users")
        
        user = self.users.get(username)
        if user:
            user.is_active = False
            self._save_users()
            print(f"✓ Deactivated user: {username}")
            return True
        
        return False
    
    def activate_user(self, username: str, admin_user: User) -> bool:
        """Activate user account (admin only)."""
        if admin_user.role != "admin":
            raise PermissionError("Only admins can activate users")
        
        user = self.users.get(username)
        if user:
            user.is_active = True
            self._save_users()
            print(f"✓ Activated user: {username}")
            return True
        
        return False
    
    def list_users(self) -> List[User]:
        """List all users."""
        return list(self.users.values())
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self.users.get(username)


# Singleton instance
_user_db_instance: Optional[UserDatabase] = None


def get_user_database() -> UserDatabase:
    """Get global user database instance."""
    global _user_db_instance
    if _user_db_instance is None:
        _user_db_instance = UserDatabase()
    return _user_db_instance
