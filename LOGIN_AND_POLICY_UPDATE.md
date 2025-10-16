# Login and File Policy Updates

## Summary
Updated the AirSeal sender application to:
1. Remove default admin credentials hint from login page
2. Allow all file extensions (videos, executables, documents, images, etc.)

## Changes Made

### 1. Removed Default Credentials Hint
**File**: `src/airseal_common/admin_dialogs.py`

**Before**:
```python
# Default credentials hint
hint = QLabel("💡 Default: admin / admin123")
hint.setStyleSheet("color: #fbbf24; font-size: 11px; font-style: italic;")
hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
layout.addWidget(hint)
```

**After**:
- Removed the hint label completely
- Users must know their credentials (no default shown)

**Security Benefit**: Prevents displaying default credentials which is a security best practice.

---

### 2. Updated File Extension Policy
**File**: `src/airseal_common/policy.py`

**Before** (DEFAULT_POLICY):
```python
allowed_extensions=[".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".jpg", ".png"],
blocked_extensions=[".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr"],
max_file_size_mb=100,
allow_archives=False,
```

**After** (DEFAULT_POLICY):
```python
allowed_extensions=[],  # Empty = all extensions allowed
blocked_extensions=[],  # No blocked extensions
max_file_size_mb=500,   # Increased for video files
allow_archives=True,    # Allow compressed archives
```

**Supported File Types Now**:
- ✅ **Videos**: .mp4, .avi, .mkv, .mov, .wmv, .flv, .webm, etc.
- ✅ **Executables**: .exe, .msi, .bat, .cmd, .ps1, .sh, etc.
- ✅ **Documents**: .pdf, .docx, .xlsx, .pptx, .txt, etc.
- ✅ **Images**: .jpg, .png, .gif, .bmp, .svg, .webp, etc.
- ✅ **Audio**: .mp3, .wav, .flac, .aac, .ogg, etc.
- ✅ **Archives**: .zip, .rar, .7z, .tar, .gz, etc.
- ✅ **Any other file type**

## Policy Comparison

### Default Policy (Updated)
- **Purpose**: General use - supports all file types
- **Allowed Extensions**: ALL (empty list = no restrictions)
- **Blocked Extensions**: NONE (empty list = no restrictions)
- **Max File Size**: 500 MB
- **Archives**: Allowed
- **Antivirus Scan**: Required

### High Security Policy (Unchanged)
- **Purpose**: Sensitive environments
- **Allowed Extensions**: Only .pdf and .txt
- **Blocked Extensions**: Many (executables, scripts, archives)
- **Max File Size**: 10 MB
- **Archives**: Not allowed

### Permissive Policy (Unchanged)
- **Purpose**: Development/testing
- **Allowed Extensions**: ALL
- **Blocked Extensions**: Only .exe, .bat, .cmd, .msi
- **Max File Size**: 500 MB
- **Archives**: Allowed

## Testing

Test the updated configuration:

```powershell
# Test sender login (no default credentials shown)
$env:PYTHONPATH="$pwd\src" ; python -m airseal_sender.gui

# Try transferring different file types:
# - Video file: test.mp4
# - Executable: app.exe
# - Archive: data.zip
# - Large file: video.mkv (up to 500 MB)
```

## Security Notes

### Antivirus Scanning Still Active
Even though all file types are allowed, the system still:
- ✅ Requires antivirus scan (Windows Defender/ClamAV)
- ✅ Verifies file integrity with SHA-256 hash
- ✅ Validates cryptographic signatures
- ✅ Checks certificate chain (if certificates used)

### Risk Assessment
- **Low Risk**: Documents, images, audio files
- **Medium Risk**: Video files (large size)
- **High Risk**: Executables, scripts, archives
  - ⚠️ Antivirus scan is CRITICAL for these types
  - ⚠️ Consider using HIGH_SECURITY_POLICY if executables should be blocked

### Recommendations
1. Ensure Windows Defender or ClamAV is installed and active
2. Keep antivirus definitions up to date
3. For highly sensitive environments, use HIGH_SECURITY_POLICY instead
4. Monitor file transfer logs for suspicious file types
5. Train users to verify file sources before importing

## Reverting Changes

If you need to restrict file types again:

**To block executables only**:
```python
blocked_extensions=[".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr"],
```

**To allow only documents and images**:
```python
allowed_extensions=[".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".jpg", ".png"],
blocked_extensions=[".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr"],
```

**To use strict policy**:
Switch to HIGH_SECURITY_POLICY in your application configuration.
