# AirSeal Identity & Security Architecture

## Overview

AirSeal implements a **three-layer identity system** to ensure secure, auditable, and non-repudiable file transfers across air-gapped networks.

---

## The Three Layers of Identity

### Layer 1: Cryptographic Key (Anonymous)
```
┌────────────────────────────────────────────────┐
│ Ed25519 Private Key                             │
│ • 256-bit cryptographic key                     │
│ • Signs every manifest                          │
│ • Proves: "Someone with this key created it"    │
│ • Problem: Keys are just random bytes           │
│ • Example: 0a7ccabc11d5d5a3...                  │
└────────────────────────────────────────────────┘
```

**What it provides:**
- **Integrity**: File hasn't been tampered with
- **Authenticity**: Signature matches the key
- **Non-repudiation**: Signer can't deny creating it

**What it DOESN'T provide:**
- **Identity**: Who owns this key?
- **Trust**: Should we trust this key?

---

### Layer 2: Certificate (Identity Binding)
```
┌────────────────────────────────────────────────┐
│ X.509-Style Certificate                         │
│                                                 │
│ CERTIFICATE HOLDER:                             │
│   Name: Dr. Sarah Johnson                       │
│   Organization: City Hospital                   │
│   Station: Medical-Scan-01                      │
│   Department: Radiology                         │
│   Email: sjohnson@hospital.org                  │
│   Public Key: [Ed25519 key]                     │
│                                                 │
│ SIGNED BY (Certificate Authority):              │
│   CA Name: AirSeal Certificate Authority        │
│   CA Organization: City Hospital IT Security    │
│   CA Signature: [Cryptographic signature]       │
│                                                 │
│ VALIDITY:                                       │
│   Valid From: 2024-01-01 00:00:00              │
│   Valid Until: 2025-01-01 00:00:00             │
│   Status: VALID (245 days remaining)            │
└────────────────────────────────────────────────┘
```

**What it provides:**
- **Identity Binding**: Key → Real Person
- **Authority Trust**: CA vouches for this identity
- **Expiration**: Time-limited validity
- **Verification**: Receiver can verify CA signature

**Certificate Authority (CA) Role:**
- Issues certificates to authorized operators
- Signs each certificate with CA's private key
- Acts as trusted third party
- Revokes compromised certificates

**Real-World Analogy:**
A certificate is like a **passport** or **driver's license**:
- Government (CA) verifies your identity
- Issues official document with your photo
- Signs/stamps it (cryptographic signature)
- Others trust the government's seal

---

### Layer 3: User Account (Session Tracking)
```
┌────────────────────────────────────────────────┐
│ Logged-In User Session                          │
│                                                 │
│ Username: sjohnson                              │
│ Full Name: Dr. Sarah Johnson                    │
│ Role: OPERATOR                                  │
│ Station: Medical-Scan-01                        │
│ Organization: City Hospital                     │
│ Department: Radiology                           │
│                                                 │
│ Login Time: 2024-01-15 14:30:22                │
│ Transfer Time: 2024-01-15 14:35:18             │
│                                                 │
│ Authentication: Password (SHA-256, 10000 iter)  │
│ Failed Attempts: 0                              │
│ Account Status: Active, Not Locked              │
└────────────────────────────────────────────────┘
```

**What it provides:**
- **Authentication**: Verified user with password
- **Session Tracking**: WHO was logged in WHEN
- **Access Control**: Role-based permissions
- **Audit Trail**: Complete transfer history
- **Account Security**: Lockout after failed attempts

---

## How They Work Together

### Sender Side Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. USER LOGS IN                                          │
│    → Username: sjohnson                                  │
│    → Password: [SHA-256 hashed, 10000 iterations]       │
│    → Verify account not locked                          │
│    → Check password validity                            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. LOAD CERTIFICATE (if available)                       │
│    → Read certificate from file                          │
│    → Verify certificate with CA                          │
│    → Check expiration date                              │
│    → Extract operator identity                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. USER SELECTS FILE                                     │
│    → Choose file to transfer                            │
│    → Compute SHA-256 hash                               │
│    → Run security scan                                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. IDENTITY VALIDATION (Pre-Transfer Security Check)     │
│                                                          │
│    ✓ Check user is logged in                            │
│    ✓ Check certificate exists                           │
│    ✓ Verify certificate with CA                         │
│    ✓ Check certificate not expired                      │
│    ✓ Validate all identity fields match                 │
│                                                          │
│    → If ANY check fails: BLOCK TRANSFER                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5. SHOW CONFIRMATION DIALOG                              │
│                                                          │
│    Display to user:                                      │
│    • Their logged-in identity                           │
│    • Certificate details (if present)                   │
│    • Who signed the certificate (CA)                    │
│    • Certificate expiration                             │
│    • File to be transferred                             │
│                                                          │
│    → User must CONFIRM before proceeding                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 6. CREATE MANIFEST                                       │
│                                                          │
│    Manifest includes:                                    │
│    • File metadata (name, size, SHA-256)                │
│    • Scan results                                       │
│    • Timestamp                                          │
│    • Certificate (operator identity)                    │
│    • User info (logged-in session)                      │
│    • Cryptographic signature (private key)              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 7. GENERATE QR CODE                                      │
│    → Encode manifest as JSON                            │
│    → Display QR code for scanning                       │
└─────────────────────────────────────────────────────────┘
```

### Receiver Side Flow

```
┌─────────────────────────────────────────────────────────┐
│ 1. SCAN QR CODE                                          │
│    → Decode JSON manifest                               │
│    → Parse all fields                                   │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 2. VERIFY CRYPTOGRAPHIC SIGNATURE                        │
│    → Extract signature from manifest                     │
│    → Extract signer's public key from certificate       │
│    → Verify signature matches manifest data             │
│    → ✓ Proves integrity and authenticity                │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 3. VERIFY CERTIFICATE (if present)                       │
│    → Load CA certificate                                │
│    → Verify certificate signature by CA                 │
│    → Check certificate not expired                      │
│    → Check certificate not revoked                      │
│    → ✓ Proves identity binding                          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 4. EXTRACT IDENTITY INFORMATION                          │
│                                                          │
│    From Certificate:                                     │
│    • Operator name, organization, station               │
│    • Department, email                                  │
│    • CA who signed it                                   │
│    • Validity period                                    │
│                                                          │
│    From User Info:                                       │
│    • Username, full name, role                          │
│    • Station, organization, department                  │
│    • Transfer timestamp                                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 5. DISPLAY SECURITY SUMMARY                              │
│                                                          │
│    Show comprehensive dialog:                            │
│    ═══════════════════════════════════════════          │
│    [CERTIFICATE VERIFIED] IDENTITY                       │
│    ═══════════════════════════════════════════          │
│                                                          │
│    CERTIFICATE HOLDER:                                   │
│      Name: Dr. Sarah Johnson                            │
│      Organization: City Hospital                        │
│      Station: Medical-Scan-01                           │
│      Department: Radiology                              │
│                                                          │
│    CERTIFICATE SIGNED BY (Authority):                    │
│      CA Name: AirSeal Certificate Authority             │
│      CA Organization: City Hospital IT Security         │
│                                                          │
│    CERTIFICATE VALIDITY:                                 │
│      Status: VALID                                      │
│      Expires: 2025-01-01 00:00:00                       │
│      Days Remaining: 245                                │
│                                                          │
│    ───────────────────────────────────────────          │
│    [SESSION] USER WHO INITIATED TRANSFER                 │
│    ───────────────────────────────────────────          │
│                                                          │
│      Username: sjohnson                                 │
│      Full Name: Dr. Sarah Johnson                       │
│      Role: OPERATOR                                     │
│      Transfer Time: 2024-01-15 14:35:18                 │
│                                                          │
│    ═══════════════════════════════════════════          │
│    [OK] SECURITY CHECKS PASSED                           │
│    ═══════════════════════════════════════════          │
│      ✓ Cryptographic signature verified                 │
│      ✓ Manifest integrity confirmed                     │
│      ✓ Certificate chain verified                       │
│      ✓ Policy compliance validated                      │
│      ✓ File scan: Clean                                 │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 6. VERIFY FILE                                           │
│    → User selects file from trusted media               │
│    → Compute SHA-256 hash                               │
│    → Compare with manifest hash                         │
│    → ✓ Accept file if hashes match                      │
└─────────────────────────────────────────────────────────┘
```

---

## Security Features

### Pre-Transfer Validation (Sender)

Before ANY transfer is allowed, the system validates:

1. **User Authentication**
   - User must be logged in
   - Password verified (SHA-256, 10000 iterations)
   - Account not locked

2. **Certificate Validation** (if present)
   - Certificate exists and readable
   - Signed by trusted CA
   - Not expired
   - CA certificate available for verification

3. **Identity Confirmation**
   - User reviews their identity information
   - User reviews certificate details
   - User explicitly confirms before proceeding

**If validation fails → Transfer BLOCKED**

### Post-Receipt Verification (Receiver)

After receiving manifest, the system:

1. **Cryptographic Verification**
   - Signature validation
   - Manifest integrity check
   - Policy compliance

2. **Certificate Chain Verification** (if present)
   - CA signature validation
   - Expiration check
   - Identity extraction

3. **Security Summary Display**
   - Complete identity information
   - Certificate chain of trust
   - All security checks status

4. **File Verification**
   - SHA-256 hash comparison
   - Integrity confirmation

---

## Why This Matters

### Scenario: Medical Imaging Transfer

**Without Identity System:**
```
Receiver sees:
  File: patient_scan.dcm
  Signed by: 0a7ccabc11d5d5a3...
  
Question: WHO is 0a7ccabc11d5d5a3??? 🤷
Can we trust this?
```

**With Complete Identity System:**
```
Receiver sees:

[VERIFIED IDENTITY]
  Operator: Dr. Sarah Johnson
  Organization: City Hospital
  Station: Medical-Scan-01
  Department: Radiology
  Email: sjohnson@hospital.org

[VERIFIED BY]
  Certificate Authority: City Hospital IT Security
  Certificate Status: Valid (expires in 245 days)

[SESSION INFO]
  Logged in as: sjohnson (OPERATOR)
  Transfer time: 2024-01-15 14:35:18

[SECURITY CHECKS]
  ✓ Certificate cryptographically verified
  ✓ Signed by trusted CA
  ✓ User authenticated at sender
  ✓ File integrity verified

Question: Can we trust this?
Answer: YES - Complete chain of trust verified!
```

### Benefits

1. **Non-Repudiation**
   - Sender can't deny creating the transfer
   - Cryptographic proof of who sent it
   - Timestamp of when it was sent

2. **Accountability**
   - Full audit trail
   - Know exactly who transferred what, when
   - Role-based access control

3. **Trust**
   - Certificate Authority vouches for identity
   - Receiver can verify the CA signature
   - Chain of trust from CA → Certificate → Transfer

4. **Compliance**
   - HIPAA-compliant identity tracking
   - SOC 2 audit requirements
   - Regulatory compliance for healthcare/defense

5. **Security**
   - Pre-transfer validation prevents unauthorized transfers
   - Certificate expiration limits exposure
   - Account lockout prevents brute force attacks

---

## Certificate Generation

### Admin can generate certificates for users:

```
1. Admin → Menu → "Generate Certificate"

2. Select user from dropdown

3. Fill in operator details:
   - Operator Name: Dr. Sarah Johnson
   - Organization: City Hospital
   - Station ID: Medical-Scan-01
   - Department: Radiology
   - Email: sjohnson@hospital.org
   - Validity: 365 days

4. System:
   - Generates Ed25519 key pair for operator
   - Creates certificate with operator identity
   - Signs certificate with CA private key
   - Saves certificate and key to disk

5. Result:
   - Certificate: username_certificate.json
   - Private Key: username_private_key.pem
   - User can now make verified transfers
```

### Certificate Authority (CA) Setup

First time setup creates CA:
```
1. Admin requests certificate generation

2. System checks for CA certificate

3. If not found:
   - Generate CA key pair
   - Create self-signed CA certificate
   - Save CA cert and key
   - Valid for 10 years

4. CA is now ready to issue operator certificates
```

---

## Password Security

### Strong Password Requirements

- **Minimum 12 characters**
- **Must contain:**
  - At least one UPPERCASE letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character (!@#$%^&*)
- **Cannot be common passwords** (password, admin123, etc.)

### Password Hashing

```python
# 10,000 iterations of SHA-256
def _hash_password(password, salt):
    salted = f"{salt}{password}{salt}".encode('utf-8')
    result = salted
    for _ in range(10000):  # Slow down brute force attacks
        result = hashlib.sha256(result).digest()
    return result.hex()
```

### Account Lockout

- **5 failed login attempts** → Account locked
- **Lockout duration:** 30 minutes
- **Tracks per-user:** Failed attempts, lockout timestamp
- **Prevents:** Brute force password attacks

### Default Admin Password

- **No hardcoded password**
- **Random 16-character password** generated on first run
- **Saved to secure file:** `.admin_initial_password.txt`
- **User must change** on first login

---

## File Locations

### Certificates
```
test_certificates/
  ├── ca_certificate.json           # CA certificate (public)
  ├── ca_private_key.pem            # CA private key (PROTECT!)
  └── [username]/
      ├── [username]_certificate.json    # User certificate
      └── [username]_private_key.pem     # User private key (PROTECT!)
```

### User Database
```
C:\ProgramData\AirSeal\users\
  ├── users.json                    # User accounts database
  └── .admin_initial_password.txt   # Temporary admin password
```

---

## Security Best Practices

### For Administrators

1. **Protect CA Private Key**
   - Store CA private key securely
   - Backup to encrypted location
   - Never transmit over network

2. **Certificate Lifecycle**
   - Issue certificates with appropriate validity (365 days)
   - Review and revoke compromised certificates
   - Track certificate expirations

3. **User Management**
   - Create unique accounts for each operator
   - Assign appropriate roles (admin/operator/viewer)
   - Review user accounts regularly
   - Disable inactive accounts

4. **Audit Trail**
   - Review transfer logs regularly
   - Investigate suspicious activity
   - Maintain audit trail for compliance

### For Operators

1. **Password Security**
   - Use strong, unique passwords
   - Don't share passwords
   - Change password if compromised

2. **Certificate Protection**
   - Protect private key file
   - Don't share certificate/key with others
   - Report lost/stolen certificates immediately

3. **Transfer Confirmation**
   - Always review identity confirmation dialog
   - Verify certificate is valid
   - Confirm file is correct before proceeding

4. **Physical Security**
   - Lock workstation when away
   - Don't leave sender application unattended
   - Protect QR codes from unauthorized viewing

---

## Troubleshooting

### Certificate Validation Failed

**Symptom:** "Certificate validation failed" error when attempting transfer

**Solutions:**
1. Check CA certificate exists: `test_certificates/ca_certificate.json`
2. Verify certificate not expired
3. Ensure certificate signed by same CA
4. Regenerate certificate if corrupted

### No Certificate Warning

**Symptom:** Transfer shows "WARNING: No certificate"

**Impact:** Transfer works but identity not cryptographically verified

**Solution:** Admin should generate certificate for user

### Account Locked

**Symptom:** "Account locked. Try again in X minutes"

**Cause:** 5 failed login attempts

**Solution:**
1. Wait 30 minutes for automatic unlock
2. Or admin can reset password in User Management

### Certificate Expired

**Symptom:** "Certificate has EXPIRED" error

**Solution:** Admin must generate new certificate with fresh validity period

---

## Compliance & Standards

### Standards Implemented

- **NIST SP 800-63B:** Password strength and account lockout
- **X.509-style certificates:** Industry-standard identity binding
- **Ed25519 signatures:** Modern elliptic curve cryptography
- **SHA-256 hashing:** Secure cryptographic hashing
- **JSON Web Signature (JWS) style:** Standard manifest signing

### Compliance Support

- **HIPAA:** Identity tracking, audit trails, access control
- **SOC 2:** User authentication, non-repudiation, audit logging
- **ISO 27001:** Access control, cryptographic controls
- **GDPR:** User accountability, data integrity

---

## Summary

AirSeal's three-layer identity system provides:

✅ **Cryptographic Security** - Ed25519 signatures prove authenticity  
✅ **Identity Verification** - Certificates bind keys to real people  
✅ **Authority Trust** - CA vouches for identities  
✅ **Session Tracking** - Know who was logged in when  
✅ **Audit Trail** - Complete transfer history  
✅ **Pre-Transfer Validation** - Block unauthorized transfers  
✅ **Chain of Trust** - Verify from CA → Certificate → User → File  
✅ **Compliance Ready** - Meets regulatory requirements  

This architecture ensures that every transfer is:
- **Authentic** (cryptographically signed)
- **Identified** (bound to a real person)
- **Authorized** (user authenticated and certificate valid)
- **Auditable** (complete tracking information)
- **Non-repudiable** (sender can't deny it)

Perfect for high-security environments like healthcare, defense, and finance.
