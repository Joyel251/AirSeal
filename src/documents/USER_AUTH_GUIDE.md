# AirSeal User Authentication & Certificate System

## Overview

AirSeal now includes a complete user authentication and certificate management system for enhanced security and accountability. This document explains the new features and how to use them.

## Features Added

### 1. User Authentication System ✅
- **Secure Login**: All users must authenticate before using the sender application
- **Role-Based Access Control**: Three user roles (Admin, Operator, Viewer)
- **Password Protection**: SHA-256 hashed passwords with random salts
- **User Database**: Persistent user storage with full CRUD operations

### 2. User Management (Admin Only) ✅
- **Add Users**: Create new user accounts with roles and permissions
- **Edit Users**: Modify user information and roles
- **Reset Passwords**: Admins can reset passwords for any user
- **Deactivate/Activate**: Temporarily disable user accounts
- **Delete Users**: Remove user accounts permanently

### 3. Certificate Management ✅
- **Certificate Generation**: Admins can generate certificates for operators
- **Identity Binding**: Certificates bind operator identity to public keys
- **CA Verification**: Receivers verify certificates against trusted CA
- **Identity Display**: Receivers show verified operator name, station, organization

## User Roles

### Admin
- Full access to all features
- Can manage users (add, edit, delete, reset passwords)
- Can generate certificates for operators
- Can perform file transfers

### Operator
- Can perform file transfers
- Cannot manage users
- Cannot generate certificates

### Viewer
- Read-only access (future feature)
- Can view logs and history
- Cannot perform transfers

## Getting Started

### First-Time Setup

1. **Default Admin Account**
   - Username: `admin`
   - Password: `admin123`
   - **⚠️ CHANGE THIS PASSWORD IMMEDIATELY!**

2. **Change Default Password**
   - Login as admin
   - Go to File → Change Password
   - Enter new secure password

3. **Create User Accounts**
   - Click "👥 Manage Users" in toolbar
   - Click "➕ Add User"
   - Fill in user details:
     - Username (required)
     - Password (min 8 characters)
     - Full Name (required)
     - Role (admin/operator/viewer)
     - Email (optional)
     - Station ID (optional)
     - Organization (optional)
     - Department (optional)

### Daily Operations

#### For Operators

1. **Login**
   - Launch AirSeal Sender
   - Enter your username and password
   - Click "Login"

2. **Perform File Transfer**
   - Once logged in, use sender normally
   - Your identity is automatically included in manifests
   - Receivers will see your name and station

3. **Logout**
   - Close the application
   - Next launch will require login again

#### For Administrators

1. **Manage Users**
   - Login as admin
   - Click "👥 Manage Users" in toolbar
   - Perform user management tasks:
     - Add new users
     - Reset forgotten passwords
     - Deactivate compromised accounts
     - Delete obsolete accounts

2. **Generate Certificates** (Command Line)
   ```powershell
   # Create Root CA (one-time setup)
   python -m airseal_common.cert_admin create-ca --name "Your Organization CA" --output ./certificates
   
   # Issue certificate to operator
   python -m airseal_common.cert_admin issue \
       --ca-dir ./certificates/ca \
       --operator "Dr. Sarah Johnson" \
       --station-id "Medical-Scan-01" \
       --organization "City Hospital" \
       --department "IT Security" \
       --email "sjohnson@hospital.org" \
       --validity-days 365
   ```

## Security Features

### Password Security
- **Hashing**: SHA-256 with random salts (32 bytes)
- **Minimum Length**: 8 characters required
- **Storage**: Hashes stored in `C:/ProgramData/AirSeal/users/users.json`
- **Validation**: Constant-time comparison prevents timing attacks

### Certificate Security
- **Cryptographic Binding**: Ed25519 signatures bind identity to keys
- **CA Trust Chain**: Receivers verify certificates against trusted CA
- **Expiration**: Certificates have configurable validity periods
- **Revocation**: CRL support for revoking compromised certificates

### Access Control
- **Role-Based**: Different permissions for admin/operator/viewer
- **Session Management**: User identity tracked throughout session
- **Audit Trail**: All actions logged with user attribution

## File Locations

### User Database
- **Windows**: `C:/ProgramData/AirSeal/users/users.json`
- **Linux**: `/var/lib/airseal/users/users.json`
- **Permissions**: Readable only by AirSeal process

### Certificates
- **CA Certificate**: `C:/ProgramData/AirSeal/certificates/ca_certificate.json`
- **Sender Certificate**: `C:/ProgramData/AirSeal/certificates/sender_certificate.json`
- **CA Private Key**: **MUST BE STORED OFFLINE IN SECURE VAULT**

## Receiver Changes

The receiver now displays verified sender identity:

**Before Certificate System:**
```
Signer: 0a7ccabc11d5d5a3... (fingerprint only)
```

**After Certificate System:**
```
✅ VERIFIED SENDER IDENTITY:
  👤 Operator: Dr. Sarah Johnson
  🏢 Organization: City Hospital
  🖥️  Station: Medical-Scan-01
  📁 Department: IT Security
  📧 Email: sjohnson@hospital.org
```

## API Reference

### UserDatabase

```python
from airseal_common import get_user_database

user_db = get_user_database()

# Create user
user = user_db.create_user(
    username="sjohnson",
    password="SecurePass123!",
    role="operator",
    full_name="Dr. Sarah Johnson",
    email="sjohnson@hospital.org",
    station_id="Medical-Scan-01",
    organization="City Hospital",
    department="IT Security"
)

# Authenticate
user = user_db.authenticate("sjohnson", "SecurePass123!")
if user:
    print(f"Logged in: {user.full_name}")

# List users
for user in user_db.list_users():
    print(f"{user.username}: {user.full_name} ({user.role})")
```

### User Object

```python
@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    role: str  # "admin", "operator", "viewer"
    full_name: str
    email: Optional[str]
    station_id: Optional[str]
    organization: str
    department: str
    created_at: float
    last_login: Optional[float]
    is_active: bool
```

## Testing

### Test User System
```powershell
python test_user_system.py
```

### Test Login UI
```powershell
# Run sender (will show login dialog)
python -m airseal_sender.gui
```

### Test Certificate System
```powershell
# Generate test certificates
python setup_test_certificates.py

# Run sender and receiver to test end-to-end
python -m airseal_sender.gui
python -m airseal_receiver.gui
```

## Troubleshooting

### "Login Failed" Error
- Check username and password are correct
- Verify user account is active (not deactivated)
- Check user database exists in `C:/ProgramData/AirSeal/users/`

### "Access Denied" for Admin Features
- Verify you're logged in as admin role
- Check user database for your role: `python test_user_system.py`

### "Certificate Verification Failed"
- Ensure CA certificate is loaded on receiver
- Check certificate not expired (`days_until_expiry`)
- Verify certificate not in CRL (revoked)
- Check certificate signed by correct CA

### User Database Corrupted
1. Backup current database if possible
2. Delete `C:/ProgramData/AirSeal/users/users.json`
3. Restart application (will create default admin)
4. Recreate user accounts

## Migration Guide

### Upgrading from Previous Version

1. **No Existing Users**: Fresh installations automatically create default admin account

2. **Existing Installations**:
   - First launch will create default admin account
   - Login with `admin` / `admin123`
   - Create operator accounts for existing users
   - Change default admin password

3. **Certificate Migration**:
   - Existing fingerprint-based verification still works
   - Certificates are optional enhancement
   - Gradually migrate to certificate system

## Security Best Practices

### For Administrators

1. **Change Default Password**
   - Do this immediately on first login
   - Use strong password (12+ characters, mixed case, numbers, symbols)

2. **Secure CA Private Key**
   - Store offline in hardware security module (HSM)
   - Never store on networked computers
   - Keep physical backups in secure vault

3. **Regular Certificate Rotation**
   - Issue certificates with 1-year validity
   - Renew before expiration
   - Revoke compromised certificates immediately

4. **User Account Hygiene**
   - Deactivate accounts when users leave
   - Review user list quarterly
   - Reset passwords if compromise suspected

5. **Audit Logging**
   - Monitor login attempts
   - Review user management actions
   - Track certificate issuance

### For Operators

1. **Protect Your Password**
   - Don't share with anyone
   - Don't write it down
   - Don't use on other systems

2. **Report Compromises**
   - Notify admin immediately if password compromised
   - Report lost/stolen devices
   - Request password reset if uncertain

3. **Workstation Security**
   - Lock screen when away
   - Don't let others use your account
   - Logout at end of shift

## Future Enhancements

- [ ] Password complexity requirements (configurable)
- [ ] Multi-factor authentication (MFA)
- [ ] LDAP/Active Directory integration
- [ ] Certificate generation UI in sender
- [ ] Automatic certificate renewal
- [ ] Hardware security module (HSM) support
- [ ] Audit log viewer in UI
- [ ] Password expiration policy
- [ ] Account lockout after failed attempts
- [ ] Session timeout after inactivity

## Support

For issues or questions:
1. Check this documentation
2. Run test scripts to verify system status
3. Check log files for error messages
4. Contact system administrator

---

**Document Version**: 1.0  
**Last Updated**: October 16, 2025  
**Author**: AirSeal Security Team
