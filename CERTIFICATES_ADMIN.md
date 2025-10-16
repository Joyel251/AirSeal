# AirSeal Certificate System - Admin Guide

## 🎯 Overview

This guide shows **security administrators** how to set up and manage the certificate-based identity system for AirSeal in production environments.

---

## 🔐 What Certificates Solve

### **Problem:**
In the basic demo, receivers only see:
- `Fingerprint: abc123...`
- No way to know **WHO** sent the file
- Anyone could claim to be "Dr. Johnson"

### **Solution:**
Certificates cryptographically bind:
- Public key → Identity (name, station, organization)
- Signed by trusted CA
- Can't be forged
- Shows on receiver UI securely

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────┐
│ ROOT CA (Organization Security)                             │
│ "City Hospital Root CA"                                     │
│ ├─ Private key (in vault, offline)                          │
│ └─ Public cert (distributed to all receivers)               │
└──────────────────────┬─────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────▼───┐   ┌────▼───┐   ┌────▼───┐
    │ Scan-01│   │ Scan-02│   │ Scan-03│
    │ Dr. J  │   │ Dr. S  │   │ Admin  │
    └────────┘   └────────┘   └────────┘
    Each gets certificate signed by Root CA
```

---

## 📋 Admin Workflow

### **STEP 1: One-Time Setup - Create Root CA**

#### Run This Command (Once):
```powershell
cd C:\Users\aarinlourdu\Music\airseal

$env:PYTHONPATH="$pwd\src"
python -m airseal_common.cert_admin create-ca `
    --name "City Hospital Root CA" `
    --output ./certificates
```

#### What This Creates:
```
certificates/
└── ca/
    ├── ca_private_key.pem     ⚠️ SECURE THIS! (offline vault)
    └── ca_certificate.json    📀 Distribute to receivers
```

#### Security Notes:
- **ca_private_key.pem**: Store offline in secure vault (HSM, encrypted USB)
- **ca_certificate.json**: Distribute to ALL receivers via CD/USB
- Only bring private key online to issue/revoke certificates

---

### **STEP 2: Issue Certificate to Scanning Station**

#### For Each Sender/Station:

```powershell
python -m airseal_common.cert_admin issue `
    --ca-dir ./certificates/ca `
    --operator "Dr. Sarah Johnson" `
    --station-id "Medical-Scan-01" `
    --organization "City Hospital" `
    --department "IT Security" `
    --email "sjohnson@hospital.org" `
    --permissions "medical_systems,patient_records" `
    --validity-days 365
```

#### What This Creates:
```
certificates/
└── ca/
    ├── issued_certificates/
    │   └── Medical-Scan-01_abc123def456.json  📜 Give to sender
    └── sender_keys/
        └── Medical-Scan-01/
            └── private_key.pem  🔑 Give to sender (SECURE!)
```

#### Distribution:
1. **Certificate + Private Key**: Give to Dr. Johnson on encrypted USB
2. **Instructions**: Tell sender to load these into AirSeal Sender app
3. **Validity**: Certificate expires in 365 days (renew annually)

---

### **STEP 3: Distribute CA Cert to Receivers**

#### Physical Distribution:
```
1. Copy ca_certificate.json to CD-ROM/USB
2. Hand-deliver to each receiver station
3. Receiver admin loads into:
   C:\ProgramData\AirSeal\ca\trusted_ca.json
```

#### On Receiver Machine:
```powershell
# Copy CA cert to receiver
Copy-Item certificates\ca\ca_certificate.json `
    C:\ProgramData\AirSeal\ca\trusted_ca.json
```

Now receiver trusts all certificates signed by this CA!

---

### **STEP 4: When Station Compromised - Revoke Certificate**

#### If Dr. Johnson's laptop is stolen:

```powershell
python -m airseal_common.cert_admin revoke `
    --ca-dir ./certificates/ca `
    --serial abc123def456 `
    --reason "Station compromised - laptop stolen"
```

#### What This Does:
- Marks certificate as revoked
- Updates Certificate Revocation List (CRL)
- Creates `crl.json` for distribution

#### Distribute Updated CRL:
```powershell
# Copy CRL to CD/USB
Copy-Item certificates\ca\crl.json Z:\crl.json

# Physical distribution to each receiver
# Receivers load into: C:\ProgramData\AirSeal\ca\crl.json
```

**Result:** Dr. Johnson's old certificate stops working immediately on all receivers

---

### **STEP 5: List All Certificates**

#### View All Issued Certs:
```powershell
python -m airseal_common.cert_admin list `
    --ca-dir ./certificates/ca
```

#### Example Output:
```
📜 Issued Certificates:

✅ Valid Medical-Scan-01 - Dr. Sarah Johnson
   Serial: abc123def456
   Organization: City Hospital
   Valid: 2024-01-01 to 2025-01-01
   Days left: 287

🚫 REVOKED Medical-Scan-02 - Dr. John Smith
   Serial: def456ghi789
   Organization: City Hospital
   Valid: 2024-01-01 to 2025-01-01
   Days left: 150
   Revocation reason: Station compromised - laptop stolen

⏰ Expired IT-Admin-03 - J. Admin
   Serial: ghi789jkl012
   Organization: City Hospital
   Valid: 2023-01-01 to 2024-01-01
   Days left: -65
```

---

## 🔄 Certificate Lifecycle

### **Issuance:**
1. Admin creates certificate for operator
2. Binds identity (name, station, org) to public key
3. Signs with CA private key
4. Distributes cert + private key to sender

### **Usage:**
1. Sender includes certificate in manifest
2. Receiver verifies certificate chain (CA → Sender)
3. Receiver displays verified identity on UI
4. Transfer proceeds with accountability

### **Renewal:**
1. Certificates expire (recommended: 6-12 months)
2. Before expiry, admin issues new certificate
3. Sender updates to new cert
4. Old cert expires naturally

### **Revocation:**
1. If compromised, admin revokes certificate
2. Updates CRL (Certificate Revocation List)
3. Distributes CRL to all receivers
4. Old cert rejected immediately

---

## 📊 Certificate Fields

### **What's In a Certificate:**
```json
{
  "serial_number": "abc123def456",
  "subject": {
    "operator_name": "Dr. Sarah Johnson",
    "station_id": "Medical-Scan-01",
    "organization": "City Hospital",
    "department": "IT Security",
    "email": "sjohnson@hospital.org",
    "permissions": ["medical_systems", "patient_records"]
  },
  "public_key_fingerprint": "a3f5e8b2c1d4...",
  "issuer_name": "City Hospital Root CA",
  "issuer_fingerprint": "9f2c3e8a...",
  "not_before": 1704067200.0,
  "not_after": 1735689600.0,
  "revoked": false,
  "signature": "ed25519-signature..."
}
```

### **Can't Be Forged Because:**
- Signature proves CA issued it
- Changing ANY field breaks signature
- Only CA has private key to sign
- CA private key secured offline

---

## 🖥️ What Receiver Sees

### **Before (Demo - No Certificates):**
```
Fingerprint: abc123...
(That's it - no identity info)
```

### **After (Production - With Certificates):**
```
┌─────────────────────────────────────┐
│  ✅ MANIFEST VERIFIED                │
├─────────────────────────────────────┤
│  Sender Information:                │
│                                     │
│  👤 Operator: Dr. Sarah Johnson     │
│  🏢 Organization: City Hospital     │
│  🏥 Department: IT Security         │
│  🖥️  Station: Medical-Scan-01       │
│  📧 Email: sjohnson@hospital.org    │
│  🔑 Fingerprint: a3f5e8b2...        │
│                                     │
│  Certificate:                       │
│  📅 Valid: 2024-01-01 to 2025-01-01│
│  ⏰ Expires in: 287 days            │
│  ✅ Issued by: City Hospital Root CA│
│  ✅ Not revoked                      │
│                                     │
│  File: patient_records.zip          │
│  Scan: Clean                        │
│  Policy: medical_systems_v1         │
└─────────────────────────────────────┘
```

**All info comes from verified certificate - can't be faked!**

---

## 🔒 Security Best Practices

### **CA Private Key:**
- ✅ Store offline in HSM or encrypted vault
- ✅ Only connect to air-gapped admin machine
- ✅ Use when issuing/revoking certificates
- ✅ Backup encrypted to multiple locations
- ❌ Never on networked machine
- ❌ Never in cloud storage

### **Certificate Validity:**
- ✅ Short periods (6-12 months)
- ✅ Forces periodic renewal
- ✅ Limits damage if compromised
- ❌ Don't use multi-year certs

### **Physical Distribution:**
- ✅ CD-ROM (write-once, tamper-evident)
- ✅ Encrypted USB with access logs
- ✅ Hand-delivered by authorized personnel
- ✅ Signed delivery receipts
- ❌ Never via email/network

### **Revocation:**
- ✅ Immediate revocation when compromised
- ✅ Monthly CRL updates minimum
- ✅ Emergency CRL distribution process
- ✅ Track all revocations in audit log

---

## 📝 Audit Logging

### **What to Log:**
- Certificate issuances (who, when, validity)
- Certificate revocations (reason, timestamp)
- CRL distributions (destination, operator)
- CA key accesses (why, duration)

### **Where to Log:**
```
certificates/
└── ca/
    └── audit.log
```

### **Example Log Entry:**
```
2024-10-15 14:32:10 | ISSUE | Medical-Scan-01 | Dr. Sarah Johnson | 365 days | Admin: J.Smith
2024-10-15 15:45:22 | REVOKE | Medical-Scan-02 | Dr. John Smith | Reason: Laptop stolen | Admin: J.Smith
2024-10-15 16:00:00 | CRL_UPDATE | Revoked count: 3 | Distributed to: 15 receivers
```

---

## 🚨 Emergency Procedures

### **If CA Private Key Compromised:**
1. **STOP** - Disconnect CA machine from all networks
2. Generate new root CA immediately
3. Re-issue ALL certificates
4. Distribute new CA cert to all receivers
5. Revoke old CA (if possible)
6. Forensic analysis of compromise
7. Update security procedures

### **If Sender Station Compromised:**
1. Revoke certificate immediately
2. Update CRL
3. Emergency CRL distribution (within 24 hours)
4. Investigate scope of compromise
5. Issue new certificate (if station recovered)
6. Incident report and lessons learned

---

## 🎓 Training Checklist

### **For Security Admins:**
- [ ] Understand certificate concepts
- [ ] Practice CA creation
- [ ] Practice certificate issuance
- [ ] Practice revocation workflow
- [ ] Understand physical distribution
- [ ] Emergency response procedures

### **For Operators (Senders):**
- [ ] Load certificate into sender app
- [ ] Understand certificate expiry
- [ ] Renewal process
- [ ] Report compromise immediately

### **For Receivers:**
- [ ] Load CA certificate
- [ ] Update CRL monthly
- [ ] Verify identity on UI
- [ ] Report suspicious certificates

---

## 📞 Support

### **For Questions:**
- Technical: it-security@hospital.org
- Emergency: security-emergency@hospital.org
- CA Admin: ca-admin@hospital.org

### **Documentation:**
- Full admin guide: `CERTIFICATES_ADMIN.md`
- User guide: `CERTIFICATES_USER.md`
- API reference: `CERTIFICATES_API.md`

---

## ✅ Quick Reference

```powershell
# Create CA (once)
python -m airseal_common.cert_admin create-ca --name "Org Root CA" --output ./certs

# Issue cert (per station)
python -m airseal_common.cert_admin issue `
    --ca-dir ./certs/ca `
    --operator "John Doe" `
    --station-id "Station-01" `
    --organization "My Org" `
    --department "IT" `
    --validity-days 365

# Revoke cert (if compromised)
python -m airseal_common.cert_admin revoke `
    --ca-dir ./certs/ca `
    --serial abc123... `
    --reason "Compromised"

# List all certs
python -m airseal_common.cert_admin list --ca-dir ./certs/ca
```

---

**Remember:** Certificates enable **cryptographically verified identity** - the cornerstone of production air-gap security! 🔒
