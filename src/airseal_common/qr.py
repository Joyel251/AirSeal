"""
AirSeal QR Code Module

Generates and parses QR codes for:
- Nonce/Transfer ID exchange
- Signed manifests
- Import receipts
"""

from __future__ import annotations

import base64
import json
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, Any

try:
    import qrcode
    from qrcode.image.pil import PilImage
except ImportError:
    raise ImportError("qrcode library required. Install with: pip install qrcode[pil]")

try:
    from PIL import Image
except ImportError:
    raise ImportError("Pillow library required. Install with: pip install Pillow")


class QRCodeGenerator:
    """Generates QR codes."""
    
    def __init__(self, error_correction=qrcode.constants.ERROR_CORRECT_M):
        """
        Initialize QR generator.
        
        Args:
            error_correction: Error correction level (L, M, Q, H)
        """
        self.error_correction = error_correction
    
    def generate(
        self,
        data: str,
        box_size: int = 10,
        border: int = 4,
    ) -> Image.Image:
        """
        Generate a QR code image.
        
        Args:
            data: String data to encode
            box_size: Size of each QR box in pixels
            border: Border size in boxes
        
        Returns:
            PIL Image
        """
        qr = qrcode.QRCode(
            version=None,  # Auto-size
            error_correction=self.error_correction,
            box_size=box_size,
            border=border,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        return img
    
    def generate_to_file(
        self,
        data: str,
        output_path: Path,
        box_size: int = 10,
        border: int = 4,
    ) -> Path:
        """
        Generate QR code and save to file.
        
        Returns:
            Path to saved file
        """
        img = self.generate(data, box_size, border)
        img.save(output_path)
        return output_path
    
    def generate_to_bytes(
        self,
        data: str,
        box_size: int = 10,
        border: int = 4,
        format: str = "PNG",
    ) -> bytes:
        """
        Generate QR code and return as bytes.
        
        Args:
            format: Image format (PNG, JPEG, etc.)
        
        Returns:
            Image bytes
        """
        img = self.generate(data, box_size, border)
        buffer = BytesIO()
        img.save(buffer, format=format)
        return buffer.getvalue()


class QRCodeParser:
    """Parses QR codes."""
    
    def __init__(self):
        """Initialize QR parser."""
        try:
            from pyzbar import pyzbar
            self.pyzbar = pyzbar
        except ImportError:
            raise ImportError(
                "pyzbar library required for QR parsing. "
                "Install with: pip install pyzbar"
            )
    
    def parse_from_file(self, image_path: Path) -> Optional[str]:
        """
        Parse QR code from image file.
        
        Returns:
            Decoded string or None if no QR found
        """
        try:
            img = Image.open(image_path)
            return self.parse_from_image(img)
        except Exception as e:
            raise ValueError(f"Failed to parse QR code from file: {e}")
    
    def parse_from_image(self, image: Image.Image) -> Optional[str]:
        """
        Parse QR code from PIL Image.
        
        Returns:
            Decoded string or None if no QR found
        """
        decoded_objects = self.pyzbar.decode(image)
        
        if not decoded_objects:
            return None
        
        # Return first QR code found
        for obj in decoded_objects:
            if obj.type == "QRCODE":
                return obj.data.decode("utf-8")
        
        return None
    
    def parse_from_bytes(self, image_bytes: bytes) -> Optional[str]:
        """
        Parse QR code from image bytes.
        
        Returns:
            Decoded string or None if no QR found
        """
        img = Image.open(BytesIO(image_bytes))
        return self.parse_from_image(img)


class NonceQRData:
    """Data structure for nonce QR codes."""
    
    def __init__(self, transfer_id: str, nonce: str, timestamp: float):
        """Initialize nonce QR data."""
        self.transfer_id = transfer_id
        self.nonce = nonce
        self.timestamp = timestamp
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        data = {
            "type": "airseal_nonce",
            "version": "1.0",
            "transfer_id": self.transfer_id,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }
        return json.dumps(data, separators=(',', ':'))
    
    @classmethod
    def from_json(cls, json_str: str) -> NonceQRData:
        """Parse from JSON string."""
        data = json.loads(json_str)
        
        if data.get("type") != "airseal_nonce":
            raise ValueError("Invalid QR type")
        
        return cls(
            transfer_id=data["transfer_id"],
            nonce=data["nonce"],
            timestamp=data["timestamp"],
        )
    
    def generate_qr(self, generator: QRCodeGenerator) -> Image.Image:
        """Generate QR code image."""
        return generator.generate(self.to_json())


class ManifestQRData:
    """Data structure for manifest QR codes."""
    
    def __init__(self, manifest_json: str):
        """
        Initialize manifest QR data.
        
        Args:
            manifest_json: Complete signed manifest as JSON string
        """
        self.manifest_json = manifest_json
    
    def to_json(self) -> str:
        """Convert to JSON string (wraps manifest)."""
        # Parse manifest to validate
        manifest_data = json.loads(self.manifest_json)
        
        data = {
            "type": "airseal_manifest",
            "version": "1.0",
            "manifest": manifest_data,
        }
        return json.dumps(data, separators=(',', ':'))
    
    @classmethod
    def from_json(cls, json_str: str) -> ManifestQRData:
        """Parse from JSON string."""
        data = json.loads(json_str)
        
        if data.get("type") != "airseal_manifest":
            raise ValueError("Invalid QR type")
        
        manifest_json = json.dumps(data["manifest"])
        return cls(manifest_json)
    
    def generate_qr(self, generator: QRCodeGenerator) -> Image.Image:
        """Generate QR code image."""
        return generator.generate(self.to_json())
    
    def get_manifest_dict(self) -> Dict[str, Any]:
        """Get manifest as dictionary."""
        return json.loads(self.manifest_json)


class ReceiptQRData:
    """Data structure for receipt QR codes."""
    
    def __init__(self, receipt_json: str):
        """
        Initialize receipt QR data.
        
        Args:
            receipt_json: Complete signed receipt as JSON string
        """
        self.receipt_json = receipt_json
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        receipt_data = json.loads(self.receipt_json)
        
        data = {
            "type": "airseal_receipt",
            "version": "1.0",
            "receipt": receipt_data,
        }
        return json.dumps(data, separators=(',', ':'))
    
    @classmethod
    def from_json(cls, json_str: str) -> ReceiptQRData:
        """Parse from JSON string."""
        data = json.loads(json_str)
        
        if data.get("type") != "airseal_receipt":
            raise ValueError("Invalid QR type")
        
        receipt_json = json.dumps(data["receipt"])
        return cls(receipt_json)
    
    def generate_qr(self, generator: QRCodeGenerator) -> Image.Image:
        """Generate QR code image."""
        return generator.generate(self.to_json())
    
    def get_receipt_dict(self) -> Dict[str, Any]:
        """Get receipt as dictionary."""
        return json.loads(self.receipt_json)


def estimate_qr_size(data: str) -> tuple[int, int]:
    """
    Estimate QR code size for given data.
    
    Returns:
        (version, approx_data_capacity) or raises if too large
    """
    data_len = len(data.encode('utf-8'))
    
    # Rough estimates for QR versions (byte mode, M error correction)
    # Version 10: ~700 bytes
    # Version 20: ~1,700 bytes
    # Version 30: ~2,900 bytes
    # Version 40: ~4,200 bytes
    
    if data_len <= 700:
        return (10, 700)
    elif data_len <= 1700:
        return (20, 1700)
    elif data_len <= 2900:
        return (30, 2900)
    elif data_len <= 4200:
        return (40, 4200)
    else:
        raise ValueError(
            f"Data too large for QR code: {data_len} bytes "
            "(maximum ~4,200 bytes for QR version 40)"
        )


def compress_manifest_for_qr(manifest_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compress manifest data to fit in QR code.
    
    Uses shorter keys and removes unnecessary whitespace.
    """
    # Use abbreviated keys
    compressed = {
        "f": manifest_dict["filename"],
        "s": manifest_dict["size"],
        "h": manifest_dict["sha256"],
        "sc": manifest_dict["scan_status"],
        "se": manifest_dict["scan_engine"],
        "sd": manifest_dict["scan_details"],
        "t": manifest_dict["timestamp"],
        "si": manifest_dict["signer_id"],
        "p": manifest_dict["policy_id"],
        "n": manifest_dict["nonce"],
        "ti": manifest_dict["transfer_id"],
        "sig": manifest_dict.get("signature", ""),
    }
    return compressed


def decompress_manifest_from_qr(compressed: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decompress manifest from QR format.
    """
    return {
        "filename": compressed["f"],
        "size": compressed["s"],
        "sha256": compressed["h"],
        "scan_status": compressed["sc"],
        "scan_engine": compressed["se"],
        "scan_details": compressed["sd"],
        "timestamp": compressed["t"],
        "signer_id": compressed["si"],
        "policy_id": compressed["p"],
        "nonce": compressed["n"],
        "transfer_id": compressed["ti"],
        "signature": compressed.get("sig", ""),
    }
