# QR Reader Library Integration

## Summary
Updated the camera QR scanner to use **pyzbar** as the primary QR reader library instead of multiple detection methods. Pyzbar is a dedicated barcode/QR code reading library that provides fast, reliable detection.

## Changes Made

### 1. Simplified Detection Pipeline
- **Primary Method**: Pyzbar on original color frame
- **Fallback 1**: Pyzbar on grayscale (for better contrast)
- **Fallback 2**: Pyzbar with CLAHE enhancement (for low-light conditions)
- **Fallback 3**: Pyzbar with adaptive thresholding (for varied lighting)

### 2. Removed Complex Methods
- Removed WeChat QR detector (requires opencv-contrib, not always available)
- Removed OpenCV QRCodeDetector fallback (slower, less reliable)
- Simplified from 4 different detector types to 1 library with 4 preprocessing strategies

## Benefits

### Speed
- Pyzbar is optimized specifically for barcode/QR detection
- Faster than general-purpose OpenCV detectors
- Early exit on first successful decode (typically frame 1)

### Reliability
- Industry-standard library used in production systems
- Better handling of various QR formats and error correction levels
- Works with damaged or partially obscured QR codes

### Simplicity
- Single library to maintain
- Consistent behavior across different systems
- No dependency on opencv-contrib extras

## Installation
Pyzbar is already in requirements.txt:
```
pyzbar>=0.1.9
opencv-python>=4.10.0
```

## Testing
Test the updated scanner:
```powershell
$env:PYTHONPATH="$pwd\src" ; python -m airseal_receiver.gui
```

Click "Scan with Camera" and show it a QR code - it should detect within 1-3 frames using the pyzbar library.

## Technical Details

### Pyzbar Library
- Based on ZBar library (C/C++ implementation)
- Supports QR Code, EAN, UPC, Code 128, and other formats
- Returns polygon coordinates for visual feedback
- Handles rotation, perspective distortion, and partial visibility

### Preprocessing Strategies
1. **Color frame**: Best for high-quality displays
2. **Grayscale**: Reduces noise, improves edge detection
3. **CLAHE**: Enhances contrast in low-light scenes
4. **Adaptive threshold**: Handles uneven lighting conditions

Each strategy is tried in sequence with early exit on success, ensuring fast detection while maintaining robustness.

## Status Messages
- Scanning: "Scanning with pyzbar QR reader library…"
- Success: "[OK] QR code detected with pyzbar reader"
- Visual feedback: Green border around detected QR code with centroid marker
