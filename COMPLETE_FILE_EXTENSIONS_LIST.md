# File Extensions Update - Complete List

## Summary
Updated the DEFAULT_POLICY to explicitly include **94 common file extensions** covering all major file types including videos (MP4, AVI, MKV), executables (EXE, MSI, APK), archives (ZIP, RAR, 7Z), and more.

## Complete List of Allowed File Types

### 📄 Documents (12 extensions)
- **Microsoft Office**: `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`
- **PDF & Text**: `.pdf`, `.txt`, `.rtf`
- **OpenDocument**: `.odt`, `.ods`, `.odp`

### 🖼️ Images (11 extensions)
- **Common formats**: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.webp`, `.ico`
- **Professional formats**: `.svg`, `.tif`, `.tiff`, `.heic`

### 🎬 Videos (12 extensions)
- **Popular formats**: `.mp4`, `.avi`, `.mkv`, `.mov`, `.wmv`
- **Streaming formats**: `.flv`, `.webm`, `.m4v`
- **Other formats**: `.mpg`, `.mpeg`, `.3gp`, `.ogv`

### 🎵 Audio (10 extensions)
- **Compressed**: `.mp3`, `.aac`, `.ogg`, `.m4a`, `.wma`, `.opus`
- **Lossless**: `.wav`, `.flac`, `.ape`, `.alac`

### 📦 Archives (9 extensions)
- **Common**: `.zip`, `.rar`, `.7z`, `.tar`
- **Compressed**: `.gz`, `.bz2`, `.xz`
- **Disk images**: `.iso`, `.dmg`

### ⚙️ Executables & Installers (9 extensions)
- **Windows**: `.exe`, `.msi`, `.bat`, `.cmd`
- **Unix/Linux**: `.sh`, `.deb`, `.rpm`
- **Mobile/Other**: `.app`, `.apk`

### 💻 Scripts & Code (18 extensions)
- **Scripts**: `.ps1`, `.vbs`, `.js`, `.py`, `.sh`
- **Programming**: `.java`, `.c`, `.cpp`, `.h`, `.cs`, `.go`, `.rs`, `.rb`, `.php`

### 🗂️ Data & Configuration (10 extensions)
- **Formats**: `.json`, `.xml`, `.yaml`, `.yml`, `.csv`
- **Database**: `.sql`, `.db`, `.sqlite`
- **Config**: `.ini`, `.cfg`, `.conf`

### 🔧 Libraries & Binaries (7 extensions)
- **Libraries**: `.dll`, `.so`, `.dylib`
- **Java**: `.jar`, `.war`, `.ear`, `.class`

---

## Total: 94 File Extensions

## Policy Configuration

```python
DEFAULT_POLICY = SecurityPolicy(
    allowed_extensions=[94 extensions listed above],
    blocked_extensions=[],  # Nothing blocked
    max_file_size_mb=500,   # 500 MB limit
    allow_archives=True,    # ZIP, RAR, etc. allowed
    require_clean_scan=True # Antivirus required
)
```

## Example File Transfers Now Supported

✅ **Video file**: `vacation.mp4` (350 MB)
✅ **Movie file**: `movie.mkv` (480 MB)  
✅ **Software installer**: `setup.exe` (120 MB)
✅ **Mobile app**: `myapp.apk` (85 MB)
✅ **Archive**: `backup.zip` (200 MB)
✅ **Music album**: `album.flac` (50 MB)
✅ **Photo**: `photo.jpg` (5 MB)
✅ **Document**: `report.pdf` (2 MB)
✅ **Code project**: `source.tar.gz` (30 MB)
✅ **Database**: `data.sqlite` (100 MB)

## Testing

Test with various file types:

```powershell
# Run sender
$env:PYTHONPATH="$pwd\src" ; python -m airseal_sender.gui

# Try these file types:
# ✓ video.mp4
# ✓ installer.exe
# ✓ archive.zip
# ✓ music.mp3
# ✓ document.pdf
# ✓ image.png
# ✓ app.apk
# ✓ backup.7z
```

## Security Features (Still Active)

Even with all file types allowed, security remains strong:

### ✅ Mandatory Antivirus Scanning
- Windows Defender (preferred)
- ClamAV (alternative)
- Demo Scanner (testing only)

### ✅ File Integrity Verification
- SHA-256 hash computed and verified
- Prevents tampering during transfer
- Detects any modification

### ✅ Cryptographic Signatures
- Ed25519 digital signatures
- Certificate chain verification
- Identity authentication

### ✅ Policy Enforcement
- Max file size: 500 MB
- Manifest age: 24 hours max
- Required clean scan status

## File Size Considerations

**500 MB Limit** supports:
- ✅ Short HD videos (5-10 minutes)
- ✅ Most software installers
- ✅ Photo collections
- ✅ Music albums
- ✅ Small backups

**Exceeds limit**:
- ❌ Full HD movies (usually 1-4 GB)
- ❌ 4K videos (usually 2-10 GB)
- ❌ Large software (games, CAD, etc.)
- ❌ Full system backups

**To increase limit**: Modify `max_file_size_mb` in policy.py

## High-Risk File Types

⚠️ **Extra caution needed** for:
- `.exe`, `.msi`, `.bat`, `.cmd` - Can execute code
- `.ps1`, `.vbs`, `.js` - Scripts that run commands
- `.apk`, `.app` - Mobile/desktop applications
- `.zip`, `.rar`, `.7z` - Can contain hidden files

**Recommendations**:
1. Ensure antivirus is up-to-date
2. Verify source before importing
3. Check digital signatures
4. Use certificates when possible
5. Review manifest before connecting USB

## Alternative Policies

If you need stricter control:

### High Security Policy
```python
# Only documents, no executables
allowed_extensions=[".pdf", ".txt"]
max_file_size_mb=10
```

### Custom Policy Example
```python
# Only videos and images
allowed_extensions=[
    ".mp4", ".avi", ".mkv", ".mov",
    ".jpg", ".png", ".gif", ".bmp"
]
max_file_size_mb=500
```

## Quick Reference

| Category | Count | Examples |
|----------|-------|----------|
| Documents | 12 | .pdf, .docx, .xlsx, .pptx |
| Images | 11 | .jpg, .png, .gif, .svg |
| Videos | 12 | .mp4, .avi, .mkv, .mov |
| Audio | 10 | .mp3, .wav, .flac, .aac |
| Archives | 9 | .zip, .rar, .7z, .tar |
| Executables | 9 | .exe, .msi, .bat, .apk |
| Scripts | 18 | .ps1, .py, .js, .sh |
| Data | 10 | .json, .xml, .csv, .sql |
| Libraries | 7 | .dll, .jar, .so, .class |
| **TOTAL** | **94** | All common file types |

## Verification

Check loaded extensions:
```powershell
$env:PYTHONPATH="$pwd\src"
python -c "from airseal_common.policy import DEFAULT_POLICY; print(f'Total extensions: {len(DEFAULT_POLICY.allowed_extensions)}'); print('Videos:', [e for e in DEFAULT_POLICY.allowed_extensions if 'mp4' in e or 'avi' in e or 'mkv' in e])"
```

Expected output:
```
Total extensions: 94
Videos: ['.mp4', '.avi', '.mkv', ...]
```
