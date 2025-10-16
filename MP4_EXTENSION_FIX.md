# FIXED: MP4 Extension Not in Allowed List

## Problem
Error message: `Policy violation: File extension '.mp4' is not in allowed list`

## Root Cause
The receiver was loading an **OLD cached policy file** from disk at:
```
C:\ProgramData\AirSeal\policies\default-v1.json
```

This file was created on **October 13, 2025** (3 days ago) with the old policy that only allowed documents and images.

## Solution Applied

### ✅ Step 1: Deleted Old Cached Policy
```powershell
Remove-Item "C:\ProgramData\AirSeal\policies\default-v1.json" -Force
```

### ✅ Step 2: Regenerated Policy Files
Ran `regenerate_policies.py` to create new policy files with 94 extensions:
- **default-v1.json**: 94 extensions (MP4, EXE, ZIP, etc.)
- **high-security-v1.json**: 2 extensions (PDF, TXT only)
- **permissive-v1.json**: 0 extensions (all allowed)

### ✅ Step 3: Verified Policy File
Confirmed that `C:\ProgramData\AirSeal\policies\default-v1.json` now contains:
- ✅ Total extensions: 94
- ✅ `.mp4` is in the list
- ✅ `.exe` is in the list
- ✅ All video, executable, archive, and other file types

## How Policy Loading Works

The receiver loads policies in this order:

1. **In-Memory Defaults** (from `policy.py`)
2. **Disk Files** (from `C:\ProgramData\AirSeal\policies\*.json`) ← **Overrides in-memory!**

The disk files take precedence, so even though you updated `policy.py`, the old disk file was being used.

## Final Steps to Test

### 1. Restart Receiver
```powershell
$env:PYTHONPATH="$pwd\src" ; python -m airseal_receiver.gui
```

### 2. Restart Sender (if needed)
```powershell
$env:PYTHONPATH="$pwd\src" ; python -m airseal_sender.gui
```

### 3. Test Transfer
1. Login to sender
2. Click "Scan File"
3. Select a `.mp4` video file
4. Generate QR code
5. Scan with receiver
6. ✅ Should work without "not in allowed list" error!

## Verification Commands

### Check Policy in Memory
```powershell
$env:PYTHONPATH="$pwd\src"
python -c "from airseal_common.policy import DEFAULT_POLICY; print('.mp4 allowed?', '.mp4' in DEFAULT_POLICY.allowed_extensions)"
```
Expected: `.mp4 allowed? True`

### Check Policy on Disk
```powershell
$policy = Get-Content "C:\ProgramData\AirSeal\policies\default-v1.json" | ConvertFrom-Json
$policy.allowed_extensions -contains ".mp4"
```
Expected: `True`

### Run Full Test
```powershell
python test_policy_extensions.py
```
Expected: `✅ SUCCESS: All test files are allowed by the policy!`

## Why This Happened

1. **Initial setup** (Oct 13): Policy with limited extensions was saved to disk
2. **Code update** (Today): You updated `policy.py` with 94 extensions
3. **Problem**: Receiver loaded old file from disk (Oct 13), ignored new code (Today)
4. **Solution**: Deleted old disk file, regenerated with new policy

## Prevention

To avoid this in the future:

### Option 1: Always Regenerate After Policy Changes
```powershell
# After editing policy.py, run:
python regenerate_policies.py
```

### Option 2: Use Skip Disk Mode (Testing Only)
In code, initialize PolicyStore with:
```python
self.policy_store = PolicyStore(skip_disk=True)  # Always use in-memory policies
```

### Option 3: Delete Cached Policies Before Testing
```powershell
Remove-Item "C:\ProgramData\AirSeal\policies\*.json" -Force
```

## File Locations

| Location | Purpose |
|----------|---------|
| `src/airseal_common/policy.py` | Source code with policy definitions |
| `C:\ProgramData\AirSeal\policies\*.json` | Cached policy files (take precedence!) |
| `regenerate_policies.py` | Script to update cached files from source |
| `test_policy_extensions.py` | Test script to verify policy works |

## Summary

✅ **Old cached policy deleted** (from Oct 13)
✅ **New policy regenerated** (94 extensions)
✅ **Verified .mp4 is in policy** (on disk)
✅ **Ready to test** - restart receiver and try again!

The error should be gone now. If you still see it, make sure to restart the receiver application to load the new policy file.
