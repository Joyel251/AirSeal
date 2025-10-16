# IMPORTANT: Restart Applications After Policy Update

## Problem
You updated the policy to include `.mp4` and other extensions, but the application still shows "extension not in allowed list" error.

## Cause
The sender/receiver applications were already running when you updated the policy. They loaded the OLD policy into memory and need to be restarted.

## Solution

### ✅ STEP 1: Close All Running Applications

**Close the Sender:**
- Click the X button on the sender window
- OR press Ctrl+C in the terminal running the sender

**Close the Receiver:**
- Click the X button on the receiver window  
- OR press Ctrl+C in the terminal running the receiver

### ✅ STEP 2: Restart the Sender

```powershell
$env:PYTHONPATH="$pwd\src" ; python -m airseal_sender.gui
```

### ✅ STEP 3: Restart the Receiver

```powershell
$env:PYTHONPATH="$pwd\src" ; python -m airseal_receiver.gui
```

### ✅ STEP 4: Test with .mp4 File

Now try to transfer a `.mp4` file:
1. Login to sender (no default credentials shown)
2. Click "Scan File" 
3. Select a `.mp4` video file
4. It should scan and generate QR code successfully ✅

## Verification

Before transferring, verify the policy is loaded correctly:

```powershell
python test_policy_extensions.py
```

Expected output:
```
✅ ALLOWED    | video.mp4     | MP4 Video
✅ ALLOWED    | setup.exe     | Windows Executable
✅ ALLOWED    | backup.zip    | ZIP Archive
...
✅ SUCCESS: All test files are allowed by the policy!
```

## Why This Happens

Python applications load modules into memory at startup:
1. **At startup**: App loads `policy.py` → reads DEFAULT_POLICY → stores in memory
2. **You edit**: You change `policy.py` on disk
3. **App still running**: App still uses OLD policy from memory (not re-reading disk)
4. **After restart**: App loads fresh `policy.py` → reads NEW policy → works! ✅

## Quick Test Without Restarting

If you want to test the policy without restarting the full GUI, use this test:

```powershell
# Test single file extension
$env:PYTHONPATH="$pwd\src"
python -c "from airseal_common.policy import PolicyStore; store = PolicyStore(skip_disk=True); policy = store.get_policy('default-v1'); print('.mp4 allowed?', '.mp4' in policy.allowed_extensions)"
```

Expected: `.mp4 allowed? True`

## Common Mistakes

❌ **Don't do this**: Edit policy while app is running and expect it to work immediately
✅ **Do this**: Edit policy → Close apps → Restart apps

❌ **Don't do this**: Open multiple sender/receiver instances with different policies
✅ **Do this**: Keep only one instance running at a time

## Troubleshooting

### Still getting "not in allowed list" error?

1. **Verify policy file is saved:**
   ```powershell
   python -c "from airseal_common.policy import DEFAULT_POLICY; print(len(DEFAULT_POLICY.allowed_extensions))"
   ```
   Expected: `94`

2. **Check for cached .pyc files:**
   ```powershell
   Remove-Item -Recurse -Force src\**\__pycache__
   ```

3. **Force reload:**
   ```powershell
   python -m compileall -f src/airseal_common/policy.py
   ```

4. **Restart PowerShell terminal** and try again

### Getting different error?

If you see a different error like:
- "File too large" → Increase `max_file_size_mb` in policy
- "Antivirus scan failed" → Install Windows Defender or ClamAV
- "Policy mismatch" → Sender and receiver using different policy IDs

## Summary

✅ **Policy file updated** with 94 extensions including .mp4
✅ **Test script passes** all extension checks
✅ **Solution**: Restart sender and receiver applications
✅ **Verification**: Run `python test_policy_extensions.py`

After restart, you can transfer:
- Videos: .mp4, .avi, .mkv, .mov, etc.
- Executables: .exe, .msi, .apk, etc.
- Archives: .zip, .rar, .7z, etc.
- Any of the 94 supported file types!
