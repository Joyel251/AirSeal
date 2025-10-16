# Secure File Save - Non-Blocking Fix

## Problem
After implementing secure file save functionality, the UI was freezing/stuck at "Verifying copied file integrity..." The issue was caused by a blocking call to `compute_file_hash()` on the main UI thread.

## Root Cause
The previous implementation used a synchronous approach:
```python
# Blocking call - freezes UI
actual_hash = compute_file_hash(save_path)
```

When computing the hash of large files, this would block the main thread, causing the UI to freeze and appear unresponsive.

## Solution
Implemented a **worker thread** pattern using `QThread` to perform file operations asynchronously:

### 1. Created SecureFileSaver Worker Thread
```python
class SecureFileSaver(QThread):
    """Background worker to securely save and verify file."""
    
    progress = Signal(str)
    finished = Signal(dict)
```

This worker performs all file operations (copy, hash verification) in a separate thread, keeping the UI responsive.

### 2. Benefits of Worker Thread Approach
- ✅ **Non-Blocking**: UI remains responsive during file operations
- ✅ **Progress Updates**: Real-time status messages via signals
- ✅ **Error Handling**: Proper exception handling with user feedback
- ✅ **Cancellable**: Can add cancel functionality if needed
- ✅ **Safe**: File operations run in background without blocking Qt event loop

### 3. Implementation Details

**Worker Thread Operations:**
1. Create target directory
2. Copy file in 1MB chunks (efficient memory usage)
3. Set read-only permissions
4. Compute SHA-256 hash (CPU-intensive, now non-blocking!)
5. Verify hash matches manifest
6. Report success/failure via signals

**Main Thread Handles:**
- User interactions (buttons, dialogs)
- Progress updates from worker
- Success/error notifications
- UI updates (enable/disable buttons)

### 4. User Experience
**Before (Blocking):**
```
[User clicks Save] → UI freezes → No feedback → Eventually completes or crashes
```

**After (Non-Blocking):**
```
[User clicks Save]
→ Button disabled (prevent double-click)
→ Progress bar shows activity
→ Real-time status messages:
   - "Creating directory..."
   - "Copying file..."
   - "Setting secure file permissions..."
   - "Verifying copied file integrity..."
   - "[OK] File integrity verified"
→ Success dialog
→ Button re-enabled for re-saving
```

## Files Modified
- `src/airseal_receiver/gui.py`:
  - Added `SecureFileSaver(QThread)` class
  - Converted `_save_verified_file_securely()` to use worker thread
  - Added `_on_save_progress()` handler
  - Added `_on_save_finished()` handler

## Testing
1. Verify a file (any size)
2. Click "Save Verified File" button
3. Choose save location
4. **Observe**: 
   - UI remains responsive
   - Progress updates appear in real-time
   - Can still interact with window
   - Hash verification completes without freezing
5. **Result**: Success dialog with confirmation

## Technical Notes

### Thread Safety
- Worker thread only modifies file system
- UI updates only happen via Qt signals (thread-safe)
- No shared mutable state between threads

### Memory Efficiency
- Uses `shutil.copyfileobj()` with 1MB buffer
- Doesn't load entire file into memory
- Suitable for large files (GB+)

### Error Recovery
- If hash mismatch: Deletes corrupted file automatically
- Proper exception propagation to UI
- User gets clear error message with hash details

## Future Enhancements
- [ ] Add progress bar with percentage (track bytes copied)
- [ ] Add cancel button to stop operation mid-transfer
- [ ] Add option to queue multiple saves
- [ ] Add logging to file for audit trail

## Related Documentation
- [SECURE_FILE_SAVE.md](SECURE_FILE_SAVE.md) - Original feature implementation
- [SECURE_SAVE_SUMMARY.md](SECURE_SAVE_SUMMARY.md) - Feature overview
