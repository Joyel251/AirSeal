# Secure File Save Feature

## Overview
The receiver now includes a secure file save feature that allows verified files to be safely copied from removable media to the local system with comprehensive integrity checks and security measures.

## Features

### 1. **Automatic Prompt After Verification**
- After successful file verification, the user is prompted to save the file immediately
- Option to save later using the "Save Verified File" button

### 2. **Secure Copy Process**
```
1. Verify source file still exists on removable media
2. Prompt for save location (default: ~/Documents/AirSeal_Imports/)
3. Copy file in 1MB chunks for memory efficiency
4. Re-verify hash of copied file
5. Set read-only permissions
6. Generate audit trail
```

### 3. **Integrity Verification**
- **Before Copy**: File already verified during import process
- **After Copy**: Hash recalculated and compared with original
- **Hash Mismatch**: Automatically deletes corrupted copy for safety

### 4. **Security Measures**

#### File Permissions
- Copied files are set to **read-only** (owner + group)
- Prevents accidental modification
- Maintains audit trail integrity

#### Safe Overwrite Protection
- Warns if destination file exists
- Requires explicit confirmation to overwrite
- No silent data loss

#### Directory Creation
- Automatically creates save directories
- Default location: `~/Documents/AirSeal_Imports/`
- Maintains organized file structure

### 5. **Audit Trail**
- Logs save location in verification status
- Records hash verification result
- Links to import receipt
- Timestamps all operations

## User Interface

### Buttons
1. **"Select File to Verify"** - Choose file from removable media
2. **"Save Verified File"** - Save verified file to local system (enabled after verification)

### Workflow
```
1. Scan Manifest QR Code
   ↓
2. Connect Removable Media
   ↓
3. Select File to Verify
   ↓
4. File Verified Successfully
   ↓
5. [Prompt] Save file now? Yes/No
   ↓
6. Choose save location
   ↓
7. File copied and re-verified
   ↓
8. Success! File saved securely
```

## Technical Implementation

### Hash Verification
```python
# Original verification (from removable media)
original_hash = compute_file_hash(source_file)

# After copy verification
copied_hash = compute_file_hash(destination_file)

if original_hash != copied_hash:
    destination_file.unlink()  # Delete corrupted copy
    raise ValueError("Hash mismatch - copy corrupted")
```

### File Permissions (Unix-like systems)
```python
import stat
os.chmod(save_path, stat.S_IRUSR | stat.S_IRGRP)  # Read-only
```

### Chunked Copy
```python
import shutil
with open(source, 'rb') as src, open(dest, 'wb') as dst:
    shutil.copyfileobj(src, dst, length=1024*1024)  # 1MB chunks
```

## Security Benefits

### 1. **Air-Gap Preservation**
- File copied from removable media only after verification
- Source media can be disconnected immediately after save
- No persistent connection to untrusted media

### 2. **Integrity Guarantee**
- Double verification (before + after copy)
- Automatic cleanup of corrupted copies
- Hash stored in import receipt for future audits

### 3. **Immutability**
- Read-only permissions prevent tampering
- Clear audit trail of file origin
- Certificate and receipt linkage

### 4. **User Control**
- Explicit save confirmation
- Choose save location
- Option to save later or multiple times

## Error Handling

### Source File Not Found
```
Error: The verified file is no longer accessible
Action: Reconnect removable media and verify again
```

### Hash Mismatch After Copy
```
Error: File copy verification failed
Action: Corrupted file automatically deleted
Recommendation: Verify source media integrity
```

### Insufficient Permissions
```
Error: Cannot set file permissions
Action: File saved but permissions may not be restricted
Recommendation: Manually set read-only if needed
```

## Usage Example

### Successful Save
```
[OK] File verified successfully
[INFO] Copying to: C:\Users\John\Documents\AirSeal_Imports\report.pdf
[OK] File saved securely to: C:\Users\John\Documents\AirSeal_Imports\report.pdf
[OK] Hash verified: a3f2b1c9d8e7f6a5b4c3d2e1f0...
[OK] File permissions: Read-only

✓ Integrity verified (SHA-256 match)
✓ File permissions set to read-only
✓ Import receipt: receipt_abc123.json
```

### Save Later
```
User clicks "No" on save prompt
↓
"Save Verified File" button remains enabled
↓
User can save anytime before verifying a new file
```

## Best Practices

### For Administrators
1. Configure default save location via policy
2. Set up centralized receipt storage
3. Monitor import audit logs
4. Enforce certificate-based transfers

### For Users
1. Save files immediately after verification
2. Disconnect removable media after save
3. Verify receipt generation
4. Keep import receipts for audit trail

### For Air-Gapped Environments
1. Use offline certificate verification
2. Store receipts on secure internal storage
3. Periodic receipt archive to audit server
4. Maintain separate logs for each transfer

## Future Enhancements

### Planned Features
- [ ] Encrypted save option
- [ ] Automatic virus re-scan after save
- [ ] Cloud backup integration (for non-air-gapped)
- [ ] Batch save multiple verified files
- [ ] Custom save location policies
- [ ] File versioning support

### Under Consideration
- [ ] Digital signature on saved file
- [ ] Automatic receipt attachment to file metadata
- [ ] Integration with DLP systems
- [ ] Compliance reporting (HIPAA, GDPR, etc.)

## Testing

### Test Cases
1. ✅ Verify and save file successfully
2. ✅ Verify file, decline save, save later
3. ✅ Verify file, source media disconnected before save
4. ✅ Save to existing file with overwrite confirmation
5. ✅ Hash mismatch after copy (simulated corruption)
6. ✅ Insufficient disk space
7. ✅ Read-only destination directory
8. ✅ Multiple saves of same verified file

### Manual Testing
```powershell
# Test the receiver with secure save
$env:PYTHONPATH="$pwd\src"
python -m airseal_receiver.gui

# Workflow:
# 1. Scan manifest QR
# 2. Verify file from USB
# 3. Save to Documents/AirSeal_Imports/
# 4. Verify hash in logs
# 5. Check file permissions
# 6. Try saving again (re-save test)
```

## Troubleshooting

### "Save Verified File" button disabled
- **Cause**: No file verified yet
- **Solution**: Complete file verification first

### Permission denied when setting read-only
- **Cause**: Windows user permissions
- **Solution**: File saved successfully, manually set read-only in properties

### Hash verification failed after save
- **Cause**: Disk corruption or media error
- **Solution**: Verify source media health, re-verify and save again

## Related Documentation
- [Security Enhancements](SECURITY_ENHANCEMENTS.md) - Overall security features
- [User Auth Guide](USER_AUTH_GUIDE.md) - User authentication system
- [Certificates Admin](CERTIFICATES_ADMIN.md) - Certificate management
- [Backend Architecture](BACKEND_ARCHITECTURE.md) - Technical details
