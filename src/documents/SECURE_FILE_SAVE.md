# Secure File Save Implementation

## Overview
The receiver now implements a secure workflow where verified files must be explicitly saved by the user after full verification passes. Files are **never automatically copied** from removable media until the user confirms.

## Security Features

### 1. **Verification-First Policy**
- Files remain on removable media (USB/CD) during verification
- Hash comparison → Antivirus scan → Policy check must **ALL pass**
- Save button only enables after complete verification

### 2. **User-Controlled Save**
- Explicit "Save Verified File" button (initially disabled)
- User chooses secure destination via file dialog
- Suggested filename from manifest metadata
- Cancel option at any time

### 3. **Secure Copy Process**

#### a. **Metadata Preservation**
```python
shutil.copy2(source, destination)  # Preserves timestamps, permissions
```

#### b. **Restrictive Permissions**
**Windows:**
- Removes permission inheritance: `icacls /inheritance:r`
- Grants only current user full control: `icacls /grant:r USERNAME:F`
- Prevents unauthorized access from other accounts

**Unix/Linux:**
- Sets owner-only read/write: `chmod 600` (0o600)
- No group or world permissions

#### c. **Post-Copy Verification**
- Recomputes SHA-256 hash of saved file
- Compares with original verified hash
- **Deletes file if hash mismatch** (prevents corrupted copies)

### 4. **Large File Handling**
- Files > 10MB show progress dialog
- Non-blocking UI during copy
- Cancellation support

### 5. **State Management**
- Clears verified file state after successful save
- Disables save button until next verification
- Resets state when scanning new manifest

## Workflow

```
┌─────────────────────────────────────────┐
│ 1. Scan Manifest QR                     │
│    ↓                                     │
│    Verify signature (Ed25519)           │
│    ↓                                     │
│    Enable "Select File" button          │
└─────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────┐
│ 2. Select File from Removable Media     │
│    ↓                                     │
│    Compare hash with manifest           │
│    ↓                                     │
│    Scan with Windows Defender/ClamAV    │
│    ↓                                     │
│    Check security policy                │
│    ↓                                     │
│    Generate signed import receipt       │
│    ↓                                     │
│    ENABLE "Save Verified File" button   │
└─────────────────────────────────────────┘
                ↓
┌─────────────────────────────────────────┐
│ 3. User Clicks "Save Verified File"     │
│    ↓                                     │
│    Prompt for destination (file dialog) │
│    ↓                                     │
│    Copy with shutil.copy2               │
│    ↓                                     │
│    Set restrictive permissions          │
│    ↓                                     │
│    Verify hash after copy               │
│    ↓                                     │
│    Show success message                 │
│    ↓                                     │
│    Disable save button (clear state)    │
└─────────────────────────────────────────┘
```

## Code Changes

### `src/airseal_receiver/gui.py`

#### Added State Variables
```python
self._verified_file_path: Optional[Path] = None
self._verified_file_hash: Optional[str] = None
```

#### New Save Button
```python
self.save_file_btn = QPushButton("Save Verified File")
self.save_file_btn.setEnabled(False)  # Initially disabled
self.save_file_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
self.save_file_btn.clicked.connect(self._save_verified_file)
```

#### Updated FileVerifier
```python
# Emits source_path and verified_hash on success
self.finished.emit({
    "success": True,
    "result": result_msg,
    "source_path": str(self.file_path),
    "verified_hash": actual_hash,
    # ... other fields
})
```

#### Updated `_on_file_verified`
```python
if result["success"]:
    # Store verified file info
    self._verified_file_path = Path(result["source_path"])
    self._verified_file_hash = result["verified_hash"]
    self.save_file_btn.setEnabled(True)  # Enable save
    # ... show success message
```

#### New Method: `_save_verified_file`
```python
def _save_verified_file(self) -> None:
    """Prompt user to save the verified file to a secure location."""
    # 1. Validate verified file exists
    # 2. Prompt for save location with suggested filename
    # 3. Show progress for large files (>10MB)
    # 4. Copy with shutil.copy2 (preserves metadata)
    # 5. Set restrictive permissions (icacls on Windows, chmod 600 on Unix)
    # 6. Verify hash after copy
    # 7. Delete if hash mismatch
    # 8. Clear state and disable button
    # 9. Show confirmation message
```

## User Experience

### Before Save
```
┌────────────────────────────────────────┐
│ VERIFIED - Ready to Save               │
│                                        │
│ Filename: document.pdf                 │
│ Hash: a3f2b1c5...                      │
│ Antivirus: Windows Defender (Clean)   │
│ Receipt: receipt_20250121_143022.json │
│                                        │
│ Click 'Save Verified File' to choose  │
│ a secure destination.                  │
└────────────────────────────────────────┘

[Select File to Verify]  [Save Verified File]
                         ^^^^^^^^^^^^^^^^^^^^
                         (Enabled after verification)
```

### After Save
```
┌────────────────────────────────────────┐
│ FILE SAVED                             │
│                                        │
│ Location: document.pdf                 │
│ Verified hash: a3f2b1c5...            │
└────────────────────────────────────────┘

✓ Verified file saved securely to:
  C:\Users\alice\Documents\document.pdf
  
  Hash verified: a3f2b1c5...
```

## Security Benefits

1. **No Automatic Execution**: Files stay on removable media until explicit save
2. **Air-Gap Integrity**: Verification happens before file touches system
3. **Permission Hardening**: Saved files have minimal access rights
4. **Hash Validation**: Detects copy corruption immediately
5. **User Control**: Explicit confirmation required for file import
6. **Audit Trail**: Import receipts track all verified saves

## Edge Cases Handled

- **File already exists**: File dialog prompts for overwrite confirmation
- **Permission errors**: Shows error message, keeps verified file available for retry
- **Hash mismatch after copy**: Deletes corrupted file, shows error
- **Large files**: Progress dialog prevents UI freeze
- **Cancelled save**: Verified file remains available, user can retry
- **New manifest scan**: Clears previous verification state

## Testing Checklist

- [ ] Verify file successfully → save button enables
- [ ] Verify fails → save button stays disabled
- [ ] Save to different locations (Desktop, Documents, external drive)
- [ ] Cancel save dialog → verified file still available
- [ ] Large file (>10MB) → progress dialog appears
- [ ] Verify permissions on saved file (check with `icacls` on Windows)
- [ ] Scan new manifest → save button disables, state resets
- [ ] Hash mismatch simulation → file deleted, error shown

## Related Documentation
- `WORKFLOW_GUIDE.md` - Overall air-gapped transfer workflow
- `BACKEND_COMPLETE.md` - Backend verification logic
- `UI_IMPROVEMENTS.md` - UI/UX enhancements history
