"""AirSeal Receiver - Professional Desktop Application."""

from __future__ import annotations

import sys
import os
import time
import json
import datetime
import hashlib
from pathlib import Path
from typing import Optional
from dataclasses import asdict

from PySide6.QtCore import Qt, Signal, QThread, QTimer
from PySide6.QtGui import QColor, QFont, QTextCursor, QPixmap, QImage, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QScrollArea,  # added for scrolling
    QStyle,
)

# Import AirSeal backend
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from airseal_common import (
    KeyPair,
    TrustStore,
    NonceManager,
    NonceData,
    Manifest,
    ManifestVerifier,
    PolicyStore,
    QRCodeGenerator,
    QRCodeParser,
    NonceQRData,
    ManifestQRData,
    ImportReceipt,
    ReceiptSigner,
    compute_file_hash,
)
from airseal_common.scanner import ScannerFactory
from cryptography.hazmat.primitives import serialization


def _find_logo_path() -> Optional[Path]:
    """Return first matching logo file irrespective of case/extension."""
    root_path = Path(__file__).parent.parent.parent
    search_roots = [root_path, root_path / "src"]
    candidate_names = [
        "logo.png",
        "logo.jpg",
        "logo.jpeg",
        "Logo.png",
        "Logo.jpg",
        "Logo.jpeg",
    ]

    for root in search_roots:
        for name in candidate_names:
            path = root / name
            if path.exists():
                return path

    for root in search_roots:
        for path in sorted(root.glob("logo.*")):
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".ico"}:
                return path
    return None


def _load_app_icon() -> QIcon:
    """Load shared application icon, returning an empty icon if missing."""
    logo_path = _find_logo_path()
    if logo_path:
        icon = QIcon(str(logo_path))
        if not icon.isNull():
            return icon
    return QIcon()


def _load_logo_pixmap(max_size: int = 72) -> Optional[QPixmap]:
    """Load and scale shared logo for in-window display."""
    logo_path = _find_logo_path()
    if not logo_path:
        return None

    pixmap = QPixmap(str(logo_path))
    if pixmap.isNull():
        return None

    if pixmap.width() > max_size:
        pixmap = pixmap.scaledToWidth(max_size, Qt.TransformationMode.SmoothTransformation)
    return pixmap


class CameraScanDialog(QDialog):
    """Dialog with live camera preview for QR scanning."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan QR Code with Camera")
        self.resize(800, 600)
        app_icon = _load_app_icon()
        if not app_icon.isNull():
            self.setWindowIcon(app_icon)
        else:
            self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.qr_data = None
        self.camera_active = False
        self._qr_detector = None
        self._scan_phase = 0.0
        self._scan_direction = 1
        
        # Build UI
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Position QR code in camera view")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #22d3ee; padding: 10px;")
        layout.addWidget(title)
        
        # Camera preview
        self.preview_label = QLabel("Initializing camera...")
        self.preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label.setMinimumSize(640, 480)
        self.preview_label.setStyleSheet(
            """
            QLabel {
                background: #0f172a;
                border: 2px solid #334155;
                border-radius: 8px;
                color: #94a3b8;
                font-size: 14px;
            }
            """
        )
        layout.addWidget(self.preview_label)
        
        # Status label
        self.status_label = QLabel("Scanning... hold the QR anywhere in view")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #cbd5e1; font-size: 13px; padding: 8px;")
        layout.addWidget(self.status_label)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogCancelButton))
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet(
            """
            QPushButton {
                background: #334155;
                color: #e2e8f0;
                border: none;
                border-radius: 6px;
                padding: 10px 24px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #475569;
            }
            """
        )
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        
        # Start camera scanning
        self.timer = QTimer()
        self.timer.timeout.connect(self._scan_frame)
        self.timer.start(60)  # ~16 FPS for smoother preview/animation
        
        # Initialize camera
        try:
            import cv2
            self.cv2 = cv2
            self.cap = cv2.VideoCapture(0)
            if not self.cap.isOpened():
                raise Exception("Could not open camera")
            self.camera_active = True
            self.status_label.setText("[OK] Camera active - the code will be detected anywhere in the frame")
        except Exception as e:
            self.status_label.setText(f"[ERROR] Camera error: {str(e)}")
            self.status_label.setStyleSheet("color: #ef4444; font-size: 13px; padding: 8px;")
            self.timer.stop()
    
    def _scan_frame(self):
        """Capture and scan a frame using pyzbar QR reader library."""
        if not self.camera_active:
            return

        try:
            from pyzbar.pyzbar import decode as pyzbar_decode, ZBarSymbol
            import numpy as np

            ret, frame = self.cap.read()
            if not ret:
                return

            display_frame = frame.copy()

            decoded_text: Optional[str] = None
            polygon_points: Optional[list[tuple[int, int]]] = None

            # PRIMARY METHOD: Pyzbar QR reader library (dedicated QR/barcode scanner)
            # Try on original color frame first (pyzbar handles color internally)
            decoded_objects = pyzbar_decode(frame, symbols=[ZBarSymbol.QRCODE])
            
            if decoded_objects:
                obj = decoded_objects[0]
                decoded_text = obj.data.decode("utf-8", errors="ignore")
                if obj.polygon:
                    polygon_points = [(int(p.x), int(p.y)) for p in obj.polygon]
            
            # FALLBACK 1: Pyzbar on grayscale (if color scan didn't work)
            if decoded_text is None:
                gray = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2GRAY)
                decoded_objects = pyzbar_decode(gray, symbols=[ZBarSymbol.QRCODE])
                if decoded_objects:
                    obj = decoded_objects[0]
                    decoded_text = obj.data.decode("utf-8", errors="ignore")
                    if obj.polygon:
                        polygon_points = [(int(p.x), int(p.y)) for p in obj.polygon]

            # FALLBACK 2: Pyzbar with enhanced contrast (for low-light conditions)
            if decoded_text is None:
                gray = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2GRAY)
                # Apply CLAHE (Contrast Limited Adaptive Histogram Equalization)
                clahe = self.cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
                enhanced = clahe.apply(gray)
                decoded_objects = pyzbar_decode(enhanced, symbols=[ZBarSymbol.QRCODE])
                if decoded_objects:
                    obj = decoded_objects[0]
                    decoded_text = obj.data.decode("utf-8", errors="ignore")
                    if obj.polygon:
                        polygon_points = [(int(p.x), int(p.y)) for p in obj.polygon]

            # FALLBACK 3: Pyzbar with adaptive thresholding (for varied lighting)
            if decoded_text is None:
                gray = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2GRAY)
                adaptive = self.cv2.adaptiveThreshold(
                    gray, 255, self.cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                    self.cv2.THRESH_BINARY, 11, 2
                )
                decoded_objects = pyzbar_decode(adaptive, symbols=[ZBarSymbol.QRCODE])
                if decoded_objects:
                    obj = decoded_objects[0]
                    decoded_text = obj.data.decode("utf-8", errors="ignore")
                    if obj.polygon:
                        polygon_points = [(int(p.x), int(p.y)) for p in obj.polygon]

            # Draw detection box if QR found
            if polygon_points:
                pts = np.array(polygon_points, dtype=np.int32)
                self.cv2.polylines(display_frame, [pts], True, (0, 255, 0), 3)
                centroid = pts.mean(axis=0).astype(int)
                self.cv2.circle(display_frame, tuple(centroid), 6, (0, 255, 0), -1)

            if decoded_text:
                self.qr_data = decoded_text
                self.cv2.putText(
                    display_frame,
                    "QR code detected by pyzbar",
                    (20, 40),
                    self.cv2.FONT_HERSHEY_SIMPLEX,
                    1.0,
                    (34, 197, 94),
                    2,
                    self.cv2.LINE_AA,
                )

                frame_rgb = self.cv2.cvtColor(display_frame, self.cv2.COLOR_BGR2RGB)
                height, width, _ = frame_rgb.shape
                bytes_per_line = 3 * width
                q_img = QImage(frame_rgb.data, width, height, bytes_per_line, QImage.Format.Format_RGB888)
                pixmap = QPixmap.fromImage(q_img)
                scaled_pixmap = pixmap.scaled(
                    self.preview_label.size(),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
                self.preview_label.setPixmap(scaled_pixmap)

                self.status_label.setText("[OK] QR code detected with pyzbar reader")
                self.status_label.setStyleSheet("color: #22d3ee; font-size: 14px; font-weight: bold; padding: 8px;")

                self.timer.stop()
                QTimer.singleShot(350, self.accept)
                return

            self.status_label.setText("Scanning...")
            self.status_label.setStyleSheet("color: #cbd5e1; font-size: 13px; padding: 8px;")

            frame_rgb = self.cv2.cvtColor(display_frame, self.cv2.COLOR_BGR2RGB)
            height, width, _ = frame_rgb.shape
            bytes_per_line = 3 * width
            q_img = QImage(frame_rgb.data, width, height, bytes_per_line, QImage.Format.Format_RGB888)
            pixmap = QPixmap.fromImage(q_img)
            scaled_pixmap = pixmap.scaled(
                self.preview_label.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.preview_label.setPixmap(scaled_pixmap)

        except Exception as e:
            self.status_label.setText(f"Scan error: {str(e)}")
    
    def closeEvent(self, event):
        """Clean up camera on close."""
        self.timer.stop()
        if hasattr(self, 'cap') and self.cap.isOpened():
            self.cap.release()
        event.accept()


class NonceGenerator(QThread):
    """Background worker to generate nonce and QR."""
    
    finished = Signal(dict)  # {nonce: str, transfer_id: str, qr_pixmap: QPixmap}
    
    def __init__(self, nonce_mgr: NonceManager):
        super().__init__()
        self.nonce_mgr = nonce_mgr
    
    def run(self):
        """Generate nonce and create QR."""
        try:
            # Generate nonce
            nonce_data = self.nonce_mgr.generate_nonce()
            
            # Create QR code
            qr_generator = QRCodeGenerator()
            nonce_qr = NonceQRData(
                transfer_id=nonce_data.transfer_id,
                nonce=nonce_data.nonce,
                timestamp=nonce_data.created_at,
            )
            qr_img = qr_generator.generate(nonce_qr.to_json(), box_size=8, border=2)
            
            # Convert to QPixmap
            from io import BytesIO
            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            qr_pixmap = QPixmap()
            qr_pixmap.loadFromData(buffer.getvalue())
            
            self.finished.emit({
                "nonce": nonce_data.nonce,
                "transfer_id": nonce_data.transfer_id,
                "qr_pixmap": qr_pixmap,
            })
        except Exception as e:
            self.finished.emit({"error": str(e)})


class ManifestScanner(QThread):
    """Background worker to scan and verify manifest QR."""
    
    progress = Signal(str)
    finished = Signal(dict)  # {success: bool, manifest: dict, error: str}
    
    def __init__(
        self,
        verifier: ManifestVerifier,
        policy_store: PolicyStore,
        use_camera: bool = True,
        file_path: Optional[Path] = None
    ):
        super().__init__()
        self.verifier = verifier
        self.policy_store = policy_store
        self.use_camera = use_camera
        self.file_path = file_path
    
    def run(self):
        """Scan QR and verify manifest."""
        try:
            if self.use_camera:
                self.progress.emit("Opening camera...")
                # TODO: Camera scanning - for now use file-based
                self.progress.emit("Camera scanning not yet implemented - please use file")
                self.finished.emit({
                    "success": False,
                    "manifest": {},
                    "error": "Camera scanning not yet implemented. Please use 'Load QR from File'.",
                })
                return
            else:
                self.progress.emit(f"Reading QR from {self.file_path.name}...")
                
                # Parse QR code
                parser = QRCodeParser()
                qr_data = parser.parse_from_file(self.file_path)
                
                if not qr_data:
                    raise ValueError("No QR code found in image")
                
                self.progress.emit("[OK] QR code decoded")
                
                # Parse manifest
                manifest_qr = ManifestQRData.from_json(qr_data)
                manifest_dict = manifest_qr.get_manifest_dict()
                
                # Convert to Manifest object
                manifest = Manifest(**manifest_dict)
                
                self.progress.emit("[OK] Manifest parsed")
            
            # Verify signature and nonce
            self.progress.emit("Verifying signature...")
            success, error = self.verifier.verify_manifest(manifest, check_nonce=False)
            
            if not success:
                raise ValueError(f"Signature verification failed: {error}")
            
            self.progress.emit("[OK] Signature valid")
            
            # Check policy
            self.progress.emit("Checking policy...")
            engine = self.policy_store.get_engine(manifest.policy_id)
            
            if not engine:
                raise ValueError(f"Unknown policy: {manifest.policy_id}")
            
            complies, reason = engine.check_manifest(manifest)
            
            if not complies:
                raise ValueError(f"Policy violation: {reason}")
            
            self.progress.emit("[OK] Policy check passed")
            
            # Success
            self.finished.emit({
                "success": True,
                "manifest": asdict(manifest),
                "error": None,
            })
            
        except Exception as e:
            self.progress.emit(f"[ERROR] {str(e)}")
            self.finished.emit({
                "success": False,
                "manifest": {},
                "error": str(e),
            })


class FileVerifier(QThread):
    """Background worker to verify file against manifest."""
    
    progress = Signal(str)
    finished = Signal(dict)  # {success: bool, result: str, error: str}
    
    def __init__(
        self,
        file_path: Path,
        manifest: dict,
        policy_store: PolicyStore,
        receiver_key: KeyPair
    ):
        super().__init__()
        self.file_path = file_path
        self.manifest = manifest
        self.policy_store = policy_store
        self.receiver_key = receiver_key
    
    def run(self):
        """Verify file hash and policy."""
        try:
            # Ensure filename matches manifest; prevents bait-and-switch.
            self.progress.emit("Validating selected file name...")
            if self.file_path.name != self.manifest["filename"]:
                raise ValueError(
                    "Selected file does not match manifest filename."
                )

            # Compute file hash
            self.progress.emit("Computing file hash...")
            actual_hash = compute_file_hash(self.file_path)
            self.progress.emit(f"[OK] Hash: {actual_hash[:16]}...")
            
            # Compare with manifest
            self.progress.emit("Comparing with manifest...")
            expected_hash = self.manifest["sha256"]
            
            if actual_hash != expected_hash:
                raise ValueError(
                    f"Hash mismatch!\nExpected: {expected_hash[:16]}...\nActual: {actual_hash[:16]}..."
                )
            
            self.progress.emit("[OK] Hash matches manifest")

            # Run antivirus scan using Windows Defender when available.
            self.progress.emit("Running antivirus scan (Windows Defender preferred)...")
            scanner = ScannerFactory.get_scanner("auto")
            engine_name = getattr(scanner, "engine_name", "Unknown")
            if engine_name.lower() == "demo scanner":
                raise ValueError(
                    "No trusted antivirus engine available. Install Windows Defender or ClamAV."
                )

            scan_result = scanner.scan(self.file_path)
            status = scan_result.status.upper()
            if status == "INFECTED":
                threat_list = ", ".join(scan_result.threats_found) or scan_result.details
                raise ValueError(f"Antivirus detected threats: {threat_list}")
            if status == "ERROR":
                raise ValueError(f"Antivirus scan failed: {scan_result.details}")
            self.progress.emit(f"[OK] Antivirus scan complete ({scan_result.engine})")

            # Check policy on actual file
            self.progress.emit("Checking file policy...")
            engine = self.policy_store.get_engine(self.manifest["policy_id"])
            
            if engine:
                safe, reason = engine.check_file(self.file_path)
                if not safe:
                    raise ValueError(f"File policy check failed: {reason}")
            
            self.progress.emit("[OK] File passes policy checks")
            
            # Generate receipt
            self.progress.emit("Generating import receipt...")
            receipt = ImportReceipt(
                result="SUCCESS",
                sha256=actual_hash,
                filename=self.manifest["filename"],
                timestamp=time.time(),
                transfer_id=self.manifest["transfer_id"],
                verifier_id=self.receiver_key.get_fingerprint(),
                reason="File verified and imported successfully",
            )
            
            receipt_signer = ReceiptSigner(self.receiver_key)
            signed_receipt = receipt_signer.sign_receipt(receipt)
            receipt_path = receipt_signer.save_receipt(signed_receipt)
            
            self.progress.emit(f"[OK] Receipt saved: {receipt_path.name}")
            
            # Success
            result_msg = (
                f"File verified and imported successfully!\n\n"
                f"Filename: {self.manifest['filename']}\n"
                f"Hash: {actual_hash[:32]}...\n"
                f"Antivirus: {scan_result.engine} ({scan_result.status})\n"
                f"Receipt: {receipt_path.name}"
            )
            
            self.finished.emit({
                "success": True,
                "result": result_msg,
                "error": None,
                "scan_engine": scan_result.engine,
                "scan_status": scan_result.status,
                "source_file": str(self.file_path),
                "file_hash": actual_hash,
                "receipt_path": str(receipt_path),
            })
            
        except Exception as e:
            self.progress.emit(f"[ERROR] {str(e)}")
            self.finished.emit({
                "success": False,
                "result": "",
                "error": str(e),
            })


class SecureFileSaver(QThread):
    """Background worker to securely save and verify file."""
    
    progress = Signal(str)
    finished = Signal(dict)  # {success: bool, saved_path: str, error: str}
    
    def __init__(self, source_file: Path, save_path: Path, expected_hash: str):
        super().__init__()
        self.source_file = source_file
        self.save_path = save_path
        self.expected_hash = expected_hash
    
    def run(self):
        """Copy file securely and verify integrity."""
        try:
            import shutil
            
            # Ensure parent directory exists
            self.progress.emit(f"Creating directory: {self.save_path.parent}...")
            self.save_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file in chunks with integrity preservation
            self.progress.emit(f"Copying file to: {self.save_path.name}...")
            with open(self.source_file, 'rb') as src, open(self.save_path, 'wb') as dst:
                shutil.copyfileobj(src, dst, length=1024*1024)  # 1MB chunks
            
            # Set secure file permissions (read-only)
            self.progress.emit("Setting secure file permissions...")
            if hasattr(os, 'chmod'):
                import stat
                os.chmod(self.save_path, stat.S_IRUSR | stat.S_IRGRP)  # Read-only
            
            # Verify hash of copied file
            self.progress.emit("Verifying copied file integrity...")
            actual_hash = compute_file_hash(self.save_path)
            
            if actual_hash != self.expected_hash:
                # Hash mismatch - delete corrupted file
                self.save_path.unlink()
                raise ValueError(
                    f"File copy verification failed!\n\n"
                    f"Expected: {self.expected_hash[:32]}...\n"
                    f"Actual: {actual_hash[:32]}...\n\n"
                    f"The file may have been corrupted during copy and has been deleted for safety."
                )
            
            self.progress.emit("[OK] File integrity verified")
            
            # Success
            self.finished.emit({
                "success": True,
                "saved_path": str(self.save_path),
                "file_hash": actual_hash,
                "error": None,
            })
            
        except Exception as e:
            self.progress.emit(f"[ERROR] {str(e)}")
            self.finished.emit({
                "success": False,
                "saved_path": "",
                "file_hash": "",
                "error": str(e),
            })


class ReceiverMainWindow(QMainWindow):
    """Single-window professional receiver console."""
    
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AirSeal Receiver")
        self.resize(1200, 820)
        app_icon = _load_app_icon()
        if not app_icon.isNull():
            self.setWindowIcon(app_icon)
        
        # Initialize backend components using shared keys for testing
        from shared_keys import get_or_create_receiver_key

        self.receiver_key = get_or_create_receiver_key()
        self.receiver_fingerprint = self.receiver_key.get_fingerprint()
        self.trust_store = TrustStore()
        self.nonce_mgr = NonceManager()
        self.policy_store = PolicyStore()
        
        # Load CA certificate for certificate verification
        self.ca_certificate = self._load_ca_certificate()
        self.certificate_verifier = None
        if self.ca_certificate:
            from airseal_common.certificates import CertificateVerifier
            self.certificate_verifier = CertificateVerifier(self.ca_certificate)
            print(f"[OK] Loaded CA certificate: {self.ca_certificate.get('subject', {}).get('operator_name', 'Unknown')}")
        
        # State
        self.manifest: Optional[dict] = None
        self._manifest_verified_at: Optional[float] = None
        self._verified_file_info: Optional[dict] = None  # Store verified file info for secure save
        
        self._build_ui()
    
    def _build_ui(self) -> None:
        """Build main UI layout."""
        central = QWidget()
        central.setObjectName("backgroundPane")
        central.setStyleSheet(
            """
            QWidget#backgroundPane {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0b1120, stop:1 #111c36);
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            """
        )
        layout = QVBoxLayout(central)
        layout.setContentsMargins(44, 36, 44, 36)
        layout.setSpacing(28)

        # Wrap content in a scroll area so the UI scrolls on smaller displays
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(central)
        self.setCentralWidget(scroll)

        header_row = QHBoxLayout()
        header_row.setSpacing(18)
        header_row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addLayout(header_row)

        logo_pix = _load_logo_pixmap()
        if logo_pix is not None:
            logo_label = QLabel()
            logo_label.setPixmap(logo_pix)
            logo_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            header_row.addWidget(logo_label)

        header = QLabel("AirSeal Receiver Console")
        header.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        header_row.addWidget(header)
        header_row.addStretch()

        subheader = QLabel("Verify and import files securely from air-gapped transfer.")
        subheader.setStyleSheet("color: #94a3b8; font-size: 15px; letter-spacing: 0.3px;")
        layout.addWidget(subheader)

        # Card 1: Manifest Scan
        self.manifest_card = self._create_card(
            "1. Scan Manifest QR",
            "Scan the sender's manifest QR to validate transfer credentials.",
        )
        layout.addWidget(self.manifest_card)
        self._init_manifest_card()

        # Card 2: File Verification
        self.verify_card = self._create_card(
            "2. Verify File",
            "Select the transferred file for integrity verification.",
        )
        layout.addWidget(self.verify_card)
        self._init_verify_card()

        layout.addStretch()

    def _create_card(self, title: str, subtitle: str) -> QFrame:
        """Create a styled card container."""
        card = QFrame()
        card.setObjectName("card")
        card.setStyleSheet(
            """
            QFrame#card {
                background: rgba(17, 28, 51, 0.82);
                border-radius: 18px;
                border: 1px solid rgba(148, 163, 184, 0.22);
            }
            """
        )
        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(24)
        shadow.setColor(QColor(10, 14, 25, 160))
        shadow.setOffset(0, 12)
        card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(18)

        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 18, QFont.Weight.DemiBold))
        layout.addWidget(title_label)

        subtitle_label = QLabel(subtitle)
        subtitle_label.setWordWrap(True)
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle_label)

        return card

    def _init_manifest_card(self) -> None:
        """Initialize manifest scan card."""
        layout = self.manifest_card.layout()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        layout.addLayout(btn_row)

        self.scan_camera_btn = QPushButton("Scan with Camera")
        self.scan_camera_btn.setEnabled(True)  # Ready to scan immediately
        self.scan_camera_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_camera_btn.setStyleSheet(self._primary_button_style())
        self.scan_camera_btn.clicked.connect(self._scan_with_camera)
        btn_row.addWidget(self.scan_camera_btn)

        self.scan_file_btn = QPushButton("Load QR from File")
        self.scan_file_btn.setEnabled(True)  # Ready to scan immediately
        self.scan_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_file_btn.setStyleSheet(self._primary_button_style())
        self.scan_file_btn.clicked.connect(self._scan_from_file)
        btn_row.addWidget(self.scan_file_btn)

        self.manifest_status = QTextEdit()
        self.manifest_status.setReadOnly(True)
        self.manifest_status.setMinimumHeight(140)
        self.manifest_status.setPlaceholderText("Manifest verification status will appear here...")
        self.manifest_status.setStyleSheet(
            """
            QTextEdit {
                background: rgba(15, 23, 42, 0.55);
                border: 1px solid rgba(148, 163, 184, 0.24);
                border-radius: 12px;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                color: #f8fafc;
                padding: 12px;
            }
            """
        )
        layout.addWidget(self.manifest_status)

    def _init_verify_card(self) -> None:
        """Initialize file verification card."""
        layout = self.verify_card.layout()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        
        self.select_file_btn = QPushButton("Select File to Verify")
        self.select_file_btn.setEnabled(False)
        self.select_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.select_file_btn.setStyleSheet(self._primary_button_style())
        self.select_file_btn.clicked.connect(self._select_file_to_verify)
        btn_row.addWidget(self.select_file_btn)
        
        self.save_file_btn = QPushButton("Save Verified File")
        self.save_file_btn.setEnabled(False)
        self.save_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_file_btn.setStyleSheet(self._secondary_button_style())
        self.save_file_btn.clicked.connect(self._save_verified_file_securely)
        btn_row.addWidget(self.save_file_btn)
        
        layout.addLayout(btn_row)

        self.verify_progress = QProgressBar()
        self.verify_progress.setVisible(False)
        self.verify_progress.setRange(0, 0)
        self.verify_progress.setTextVisible(True)
        self.verify_progress.setFormat("Verifying... %p%")
        self.verify_progress.setStyleSheet(
            """
            QProgressBar {
                background: rgba(8, 47, 73, 0.45);
                border-radius: 10px;
                border: 1px solid rgba(148, 163, 184, 0.24);
                color: #e2e8f0;
                font-weight: 600;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                border-radius: 8px;
            }
            """
        )
        layout.addWidget(self.verify_progress)

        self.verify_status = QTextEdit()
        self.verify_status.setReadOnly(True)
        self.verify_status.setMinimumHeight(140)
        self.verify_status.setPlaceholderText("File verification status will appear here...")
        self.verify_status.setStyleSheet(
            """
            QTextEdit {
                background: rgba(15, 23, 42, 0.55);
                border: 1px solid rgba(148, 163, 184, 0.24);
                border-radius: 12px;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                color: #f8fafc;
                padding: 12px;
            }
            """
        )
        layout.addWidget(self.verify_status)

        self.result_label = QLabel("Waiting for file verification...")
        self.result_label.setWordWrap(True)
        self.result_label.setMinimumHeight(80)
        self.result_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_label.setStyleSheet(
            """
            QLabel {
                background: rgba(8, 47, 73, 0.4);
                border: 1px dashed rgba(148, 163, 184, 0.35);
                border-radius: 16px;
                color: #94a3b8;
                font-size: 14px;
                padding: 20px;
            }
            """
        )
        self.result_label.setText(
            "Step 1: Scan and verify the manifest.\n"
            "Keep USB/CD media disconnected until the manifest is trusted."
        )
        layout.addWidget(self.result_label)

    def _load_ca_certificate(self) -> Optional[dict]:
        """Load CA certificate for certificate verification."""
        try:
            # Try to load from standard location
            ca_cert_path = Path("C:/ProgramData/AirSeal/certificates/ca_certificate.json")
            
            if not ca_cert_path.exists():
                # Try local test location
                ca_cert_path = Path(__file__).parent.parent.parent / "test_certificates" / "ca_certificate.json"
            
            if ca_cert_path.exists():
                ca_cert_data = json.loads(ca_cert_path.read_text())
                print(f"[OK] Loaded CA certificate from: {ca_cert_path}")
                return ca_cert_data
            else:
                print("[INFO] No CA certificate found - certificate verification disabled")
                return None
                
        except Exception as e:
            print(f"WARNING: Could not load CA certificate: {e}")
            return None
    
    def _primary_button_style(self) -> str:
        """Return primary button stylesheet."""
        return """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 15px;
                font-weight: 600;
                padding: 12px 24px;
                letter-spacing: 0.5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0891b2, stop:1 #0369a1);
            }
            QPushButton:disabled {
                background: rgba(100, 116, 139, 0.3);
                color: rgba(148, 163, 184, 0.5);
            }
        """

    def _secondary_button_style(self) -> str:
        """Return secondary button stylesheet."""
        return """
            QPushButton {
                background: rgba(30, 41, 59, 0.6);
                color: #94a3b8;
                border: 1px solid rgba(148, 163, 184, 0.3);
                border-radius: 10px;
                font-size: 15px;
                font-weight: 600;
                padding: 12px 24px;
                letter-spacing: 0.5px;
            }
            QPushButton:hover {
                background: rgba(51, 65, 85, 0.8);
                border-color: rgba(148, 163, 184, 0.5);
                color: #cbd5e1;
            }
            QPushButton:pressed {
                background: rgba(71, 85, 105, 0.9);
            }
            QPushButton:disabled {
                background: rgba(30, 41, 59, 0.3);
                color: rgba(148, 163, 184, 0.3);
                border-color: rgba(148, 163, 184, 0.15);
            }
        """

    def _scan_with_camera(self):
        """Start camera-based QR scanning with live preview."""
        try:
            import cv2
            from pyzbar.pyzbar import decode as pyzbar_decode
        except ImportError:
            QMessageBox.critical(
                self, 
                "Camera Support Missing",
                "Camera scanning requires opencv-python.\n\n"
                "Install it with:\n"
                "pip install opencv-python\n\n"
                "Then restart the application."
            )
            return
        
        # Reset state while awaiting new manifest
        self.manifest = None
        self._manifest_verified_at = None
        self.select_file_btn.setEnabled(False)
        self.result_label.setText(
            "Scanning in progress. Keep removable media disconnected until verification completes."
        )

        # Create camera dialog
        dialog = CameraScanDialog(self)
        result = dialog.exec()
        
        if result == QDialog.DialogCode.Accepted and dialog.qr_data:
            # Process the scanned QR data
            self.manifest_status.clear()
            self._process_scanned_qr(dialog.qr_data)
    
    def _process_scanned_qr(self, qr_data: str):
        """Process QR data scanned from camera."""
        try:
            self._append_and_scroll(self.manifest_status, "[INFO] Processing scanned QR code...")
            
            # Parse manifest from QR data
            manifest_qr = ManifestQRData.from_json(qr_data)
            manifest_dict = manifest_qr.get_manifest_dict()
            
            # Convert to Manifest object
            manifest = Manifest(**manifest_dict)
            
            self._append_and_scroll(self.manifest_status, "[OK] Manifest parsed successfully")
            
            sender_identity = None
            cert_obj = None

            if manifest.sender_certificate:
                self._append_and_scroll(self.manifest_status, "[INFO] Verifying sender certificate...")
                if not self.certificate_verifier:
                    raise ValueError(
                        "Certificate presented but receiver has no trusted Certificate Authority metadata."
                    )

                from airseal_common.certificates import Certificate

                cert_obj = Certificate.from_dict(manifest.sender_certificate)
                is_valid, error_msg = self.certificate_verifier.verify_certificate(cert_obj)
                if not is_valid:
                    raise ValueError(f"Certificate verification failed: {error_msg}")

                if cert_obj.public_key_fingerprint and manifest.signer_id != cert_obj.public_key_fingerprint:
                    raise ValueError(
                        "Manifest signer fingerprint does not match the certificate's public key fingerprint."
                    )

                if not cert_obj.public_key_pem:
                    raise ValueError("Certificate is missing the public key information required for verification.")

                public_key = serialization.load_pem_public_key(cert_obj.public_key_pem.encode("utf-8"))
                if not self.trust_store.has_key(manifest.signer_id):
                    self.trust_store.add_key(manifest.signer_id, public_key)
                    self._append_and_scroll(
                        self.manifest_status,
                        f"[INFO] Trusted signer key derived from certificate {manifest.signer_id[:16]}...",
                    )

                sender_identity = self.certificate_verifier.extract_identity(cert_obj)
                self._append_and_scroll(self.manifest_status, "[OK] Certificate verified against trusted CA")

            # Verify signature
            self._append_and_scroll(self.manifest_status, "[INFO] Verifying digital signature...")
            verifier = ManifestVerifier(self.trust_store, self.nonce_mgr)
            success, error = verifier.verify_manifest(manifest, check_nonce=False)

            if not success:
                raise ValueError(f"Signature verification failed: {error}")

            self._append_and_scroll(self.manifest_status, "[OK] Signature verified")

            # Check policy
            self._append_and_scroll(self.manifest_status, "[INFO] Checking security policy...")
            engine = self.policy_store.get_engine(manifest.policy_id)

            if not engine:
                raise ValueError(f"Unknown policy: {manifest.policy_id}")

            complies, reason = engine.check_manifest(manifest)

            if not complies:
                raise ValueError(f"Policy violation: {reason}")

            self._append_and_scroll(self.manifest_status, "[OK] Policy check passed")

            if manifest.sender_certificate and not sender_identity:
                # Certificate was present but we could not verify it above; block transfer
                raise ValueError("Sender certificate could not be verified. Transfer rejected.")
            
            # Success - store manifest and enable file verification
            self.manifest = asdict(manifest)
            self._manifest_verified_at = time.time()
            self._append_and_scroll(self.manifest_status, "\n[OK] Manifest verified successfully!")
            self._append_and_scroll(self.manifest_status, f"  File: {self.manifest['filename']}")
            self._append_and_scroll(self.manifest_status, f"  Size: {self.manifest['size']} bytes")
            self._append_and_scroll(self.manifest_status, f"  Expected SHA-256: {self.manifest['sha256'][:16]}...")
            self._append_and_scroll(self.manifest_status, f"  Scan Result: {self.manifest['scan_status']}")
            self._append_and_scroll(self.manifest_status, f"  Policy: {self.manifest['policy_id']}")
            
            # Display verified identity with certificate details
            if sender_identity and manifest.sender_certificate:
                from airseal_common.certificates import Certificate
                cert = cert_obj or Certificate.from_dict(manifest.sender_certificate)

                self._append_and_scroll(self.manifest_status, "\n" + "="*60)
                self._append_and_scroll(self.manifest_status, "[CERTIFICATE VERIFIED] CRYPTOGRAPHICALLY VERIFIED IDENTITY")
                self._append_and_scroll(self.manifest_status, "="*60)

                # Certificate holder (operator)
                self._append_and_scroll(self.manifest_status, "\nCERTIFICATE HOLDER:")
                self._append_and_scroll(self.manifest_status, f"  Name: {sender_identity.get('operator_name', 'Unknown')}")
                self._append_and_scroll(self.manifest_status, f"  Organization: {sender_identity.get('organization', 'Unknown')}")
                self._append_and_scroll(self.manifest_status, f"  Station ID: {sender_identity.get('station_id', 'Unknown')}")
                if sender_identity.get('department'):
                    self._append_and_scroll(self.manifest_status, f"  Department: {sender_identity['department']}")
                if sender_identity.get('email'):
                    self._append_and_scroll(self.manifest_status, f"  Email: {sender_identity['email']}")
                
                # Certificate issuer (CA)
                self._append_and_scroll(self.manifest_status, "\nCERTIFICATE ISSUED BY (Authority):")
                # Handle both old format (issuer_name) and new format (issuer dict)
                if cert.issuer:
                    self._append_and_scroll(self.manifest_status, f"  CA Name: {cert.issuer.get('common_name', 'Unknown CA')}")
                    if cert.issuer.get('organization'):
                        self._append_and_scroll(self.manifest_status, f"  CA Organization: {cert.issuer['organization']}")
                elif cert.issuer_name:
                    self._append_and_scroll(self.manifest_status, f"  CA Name: {cert.issuer_name}")
                
                # Certificate validity
                self._append_and_scroll(self.manifest_status, "\nCERTIFICATE VALIDITY:")
                from datetime import datetime
                # Handle both old format (not_before/not_after) and new format (valid_from/valid_until)
                if cert.valid_from and cert.valid_until:
                    valid_from = datetime.fromisoformat(cert.valid_from.replace('Z', '+00:00'))
                    valid_until = datetime.fromisoformat(cert.valid_until.replace('Z', '+00:00'))
                elif cert.not_before and cert.not_after:
                    valid_from = datetime.fromtimestamp(cert.not_before)
                    valid_until = datetime.fromtimestamp(cert.not_after)
                else:
                    valid_from = datetime.now()
                    valid_until = datetime.now()
                
                self._append_and_scroll(self.manifest_status, f"  Valid From: {valid_from.strftime('%Y-%m-%d %H:%M:%S')}")
                self._append_and_scroll(self.manifest_status, f"  Valid Until: {valid_until.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Certificate fingerprint
                import hashlib
                import json
                cert_bytes = json.dumps(cert.to_dict(), sort_keys=True).encode()
                cert_fingerprint = hashlib.sha256(cert_bytes).hexdigest()
                self._append_and_scroll(self.manifest_status, f"  Fingerprint: {cert_fingerprint[:32]}...")
            
            # Display logged-in user info from manifest
            if self.manifest.get('user_info'):
                user_info = self.manifest['user_info']
                self._append_and_scroll(self.manifest_status, "\n" + "-"*60)
                self._append_and_scroll(self.manifest_status, "[SESSION INFO] USER WHO SENT THIS TRANSFER")
                self._append_and_scroll(self.manifest_status, "-"*60)
                self._append_and_scroll(self.manifest_status, f"\n  Full Name: {user_info.get('full_name', 'Unknown')}")
                self._append_and_scroll(self.manifest_status, f"  Username: {user_info.get('username', 'Unknown')}")
                self._append_and_scroll(self.manifest_status, f"  Role: {user_info.get('role', 'Unknown').upper()}")
                if user_info.get('station_id'):
                    self._append_and_scroll(self.manifest_status, f"  Station: {user_info['station_id']}")
                if user_info.get('organization'):
                    self._append_and_scroll(self.manifest_status, f"  Organization: {user_info['organization']}")
                if user_info.get('department'):
                    self._append_and_scroll(self.manifest_status, f"  Department: {user_info['department']}")
                
                # Timestamp
                import datetime
                timestamp = datetime.datetime.fromtimestamp(self.manifest.get('timestamp', 0))
                self._append_and_scroll(self.manifest_status, f"  Transfer Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Fallback if no identity info available
            if not sender_identity and not self.manifest.get('user_info'):
                self._append_and_scroll(self.manifest_status, "\n[WARNING] No identity information available")
                self._append_and_scroll(self.manifest_status, f"  Signer Key ID: {self.manifest.get('signer_id', 'Unknown')[:32]}...")
                self._append_and_scroll(self.manifest_status, "  (Consider requiring certificates for all transfers)")
            
            # Enable file verification
            self.select_file_btn.setEnabled(True)
            
            # Show comprehensive security summary
            self._show_security_summary(manifest, sender_identity)
            
            self._prompt_for_media_connection()
            
        except Exception as e:
            error_msg = f"Failed to process QR code: {str(e)}"
            self._append_and_scroll(self.manifest_status, f"\n[ERROR] {error_msg}")
            QMessageBox.critical(
                self,
                "QR Processing Failed",
                error_msg
            )
    
    def _scan_from_file(self):
        """Load QR from image file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select QR Image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp)",
        )
        if not file_path:
            return
        
        # Reset manifest while rescanning from file
        self.manifest = None
        self._manifest_verified_at = None
        self.select_file_btn.setEnabled(False)
        self.result_label.setText(
            "Verifying manifest from image. Do not connect removable media yet."
        )

        self.manifest_status.clear()
        # Create a verifier with the sender's key from trust store
        verifier = ManifestVerifier(self.trust_store, self.nonce_mgr)
        self.scan_worker = ManifestScanner(
            use_camera=False,
            file_path=Path(file_path),
            verifier=verifier,
            policy_store=self.policy_store
        )
        self.scan_worker.progress.connect(self._on_manifest_progress)
        self.scan_worker.finished.connect(self._on_manifest_scanned)
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_worker.start()
    
    def _on_manifest_scanned(self, result: dict):
        """Handle manifest scan completion."""
        if not result["success"]:
            self._append_and_scroll(self.manifest_status, f"\n[ERROR] {result['error']}")
            QMessageBox.critical(self, "Scan Failed", f"Failed to verify manifest:\n{result['error']}")
            return
        
        self.manifest = result["manifest"]
        self._manifest_verified_at = time.time()
        self._append_and_scroll(self.manifest_status, "\n[OK] Manifest verified successfully!")
        self._append_and_scroll(self.manifest_status, f"  File: {self.manifest['filename']}")
        self._append_and_scroll(self.manifest_status, f"  Size: {self.manifest['size']} bytes")
        self._append_and_scroll(self.manifest_status, f"  Expected SHA-256: {self.manifest['sha256'][:16]}...")
        self._append_and_scroll(self.manifest_status, f"  Scan Result: {self.manifest['scan_status']}")
        self._append_and_scroll(self.manifest_status, f"  Policy: {self.manifest['policy_id']}")
        self._append_and_scroll(self.manifest_status, f"  Signer: {self.manifest.get('signer_id', 'Unknown')[:16]}...")
        
        # Enable file verification
        self.select_file_btn.setEnabled(True)
        self._prompt_for_media_connection()
    
    def _select_file_to_verify(self):
        """Select file from USB/media to verify."""
        if not self.manifest:
            QMessageBox.warning(
                self,
                "Manifest Not Verified",
                "Do not connect removable media yet. Scan and trust the manifest QR first."
            )
            self.result_label.setText(
                "Manifest pending. Disconnect removable media and complete the QR scan."
            )
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            f"Select File: {self.manifest['filename']}",
            "",
            "All Files (*.*)",
        )
        if not file_path:
            return

        if self._manifest_verified_at and (time.time() - self._manifest_verified_at) > 600:
            proceed = QMessageBox.warning(
                self,
                "Manifest Stale",
                "The manifest was verified more than 10 minutes ago. "
                "To maximize safety, consider rescanning the QR before importing.\n\n"
                "Click Yes to proceed anyway.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if proceed != QMessageBox.StandardButton.Yes:
                return

        candidate_path = Path(file_path)
        if candidate_path.name != self.manifest["filename"]:
            QMessageBox.critical(
                self,
                "Filename Mismatch",
                "The selected file name does not match the manifest. Connect the intended media and retry."
            )
            return

        if not self._is_removable_media(candidate_path):
            QMessageBox.critical(
                self,
                "Removable Media Required",
                "Select the file directly from removable media (USB drive or optical disc)."
            )
            return

        if not candidate_path.exists():
            QMessageBox.critical(
                self,
                "File Not Found",
                "The selected file is not accessible. Ensure the media is connected and try again."
            )
            return
        
        self.verify_status.clear()
        self.verify_progress.setVisible(True)
        self.verify_progress.setRange(0, 0)
        self.select_file_btn.setEnabled(False)
        
        self.verify_worker = FileVerifier(
            candidate_path,
            self.manifest,
            self.policy_store,
            self.receiver_key
        )
        self.verify_worker.progress.connect(self._on_verify_progress)
        self.verify_worker.finished.connect(self._on_file_verified)
        self.verify_worker.finished.connect(self.verify_worker.deleteLater)
        self.verify_worker.start()
    
    def _on_file_verified(self, result: dict):
        """Handle file verification completion."""
        self.verify_progress.setVisible(False)
        self.select_file_btn.setEnabled(True)
        
        if result["success"]:
            self._append_and_scroll(self.verify_status, f"\n[OK] {result['result']}")
            self.result_label.setText("VERIFIED AND IMPORTED\n\n" + result['result'])
            self.result_label.setStyleSheet(
                """
                QLabel {
                    background: rgba(16, 185, 129, 0.15);
                    border: 2px solid rgba(52, 211, 153, 0.6);
                    border-radius: 16px;
                    color: #34d399;
                    font-size: 14px;
                    font-weight: 600;
                    padding: 20px;
                }
                """
            )
            
            # Store verified file info for secure save
            self._verified_file_info = result
            
            # Enable save button
            self.save_file_btn.setEnabled(True)
            
            # Prompt user to save file securely
            engine = result.get("scan_engine", "Antivirus")
            reply = QMessageBox.question(
                self,
                "File Verified Successfully",
                f"File verified and imported successfully!\n\n"
                f"Antivirus engine: {engine}\n"
                f"Hash: {result.get('file_hash', 'N/A')[:32]}...\n\n"
                f"Would you like to save this file securely to your local system now?\n"
                f"(You can also use the 'Save Verified File' button later)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self._save_verified_file_securely()
        else:
            self._append_and_scroll(self.verify_status, f"\n[ERROR] {result['error']}")
            self.result_label.setText("VERIFICATION FAILED\n\n" + result['error'])
            self.result_label.setStyleSheet(
                """
                QLabel {
                    background: rgba(239, 68, 68, 0.15);
                    border: 2px solid rgba(248, 113, 113, 0.6);
                    border-radius: 16px;
                    color: #f87171;
                    font-size: 14px;
                    font-weight: 600;
                    padding: 20px;
                }
                """
            )
            QMessageBox.critical(self, "Verification Failed", f"File verification failed:\n{result['error']}")
    
    def _append_and_scroll(self, editor: QTextEdit, text: str) -> None:
        editor.append(text)
        cursor = editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        editor.setTextCursor(cursor)
        editor.ensureCursorVisible()

    def _on_manifest_progress(self, msg: str) -> None:
        self._append_and_scroll(self.manifest_status, f"- {msg}")

    def _on_verify_progress(self, msg: str) -> None:
        self._append_and_scroll(self.verify_status, f"- {msg}")

    def _save_verified_file_securely(self):
        """Save verified file securely to local system with integrity checks."""
        if not self._verified_file_info:
            QMessageBox.warning(
                self,
                "No Verified File",
                "Please verify a file first before attempting to save it."
            )
            return
        
        try:
            source_file = Path(self._verified_file_info["source_file"])
            expected_hash = self._verified_file_info["file_hash"]
            filename = self.manifest["filename"]
            
            # Check if source file still exists
            if not source_file.exists():
                QMessageBox.critical(
                    self,
                    "Source File Not Found",
                    f"The verified file is no longer accessible at:\n{source_file}\n\n"
                    "Please reconnect the removable media and verify the file again."
                )
                return
            
            # Ask user where to save the file
            default_save_path = Path.home() / "Documents" / "AirSeal_Imports" / filename
            default_save_path.parent.mkdir(parents=True, exist_ok=True)
            
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Verified File Securely",
                str(default_save_path),
                "All Files (*.*)",
            )
            
            if not save_path:
                return  # User cancelled
            
            save_path = Path(save_path)
            
            # Prevent overwriting without confirmation
            if save_path.exists():
                reply = QMessageBox.question(
                    self,
                    "Overwrite File?",
                    f"The file '{save_path.name}' already exists.\n\n"
                    "Do you want to overwrite it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return
            
            # Disable save button during operation
            self.save_file_btn.setEnabled(False)
            
            # Show progress in verify status box
            self._append_and_scroll(self.verify_status, "\n[INFO] Starting secure file save...")
            self.verify_progress.setVisible(True)
            self.verify_progress.setRange(0, 0)  # Indeterminate progress
            
            # Start worker thread for secure save (non-blocking)
            self.save_worker = SecureFileSaver(source_file, save_path, expected_hash)
            self.save_worker.progress.connect(self._on_save_progress)
            self.save_worker.finished.connect(self._on_save_finished)
            self.save_worker.finished.connect(self.save_worker.deleteLater)
            self.save_worker.start()
                
        except Exception as e:
            QMessageBox.critical(
                self,
                "Secure Save Failed",
                f"Failed to start secure save:\n\n{str(e)}"
            )
            self._append_and_scroll(self.verify_status, f"\n[ERROR] Secure save failed: {str(e)}")
            self.save_file_btn.setEnabled(True)
    
    def _on_save_progress(self, msg: str):
        """Handle save progress updates."""
        self._append_and_scroll(self.verify_status, f"- {msg}")
    
    def _on_save_finished(self, result: dict):
        """Handle save completion."""
        self.verify_progress.setVisible(False)
        
        if result["success"]:
            saved_path = Path(result["saved_path"])
            file_hash = result["file_hash"]
            receipt_path = self._verified_file_info.get("receipt_path", "")
            
            self._append_and_scroll(
                self.verify_status,
                f"\n[OK] File saved securely to: {saved_path}"
            )
            self._append_and_scroll(
                self.verify_status,
                f"[OK] Hash verified: {file_hash[:32]}..."
            )
            self._append_and_scroll(
                self.verify_status,
                f"[OK] File permissions: Read-only"
            )
            
            # Re-enable save button for re-saving if needed
            self.save_file_btn.setEnabled(True)
            
            QMessageBox.information(
                self,
                "File Saved Successfully",
                f"File saved securely to:\n{saved_path}\n\n"
                f"[OK] Integrity verified (SHA-256 match)\n"
                f"[OK] File permissions set to read-only\n"
                f"[OK] Import receipt: {Path(receipt_path).name if receipt_path else 'Generated'}\n\n"
                f"The file is now safely stored on your local system."
            )
        else:
            self._append_and_scroll(
                self.verify_status,
                f"\n[ERROR] Save failed: {result['error']}"
            )
            QMessageBox.critical(
                self,
                "Secure Save Failed",
                f"Failed to save file securely:\n\n{result['error']}"
            )
            self.save_file_btn.setEnabled(True)

    def _show_security_summary(self, manifest: Manifest, sender_identity: Optional[dict]) -> None:
        """Show comprehensive security summary with certificate chain of trust."""
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QScrollArea, QWidget
        from PySide6.QtGui import QFont
        from PySide6.QtCore import Qt
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Transfer Security Summary")
        dialog.setMinimumSize(700, 600)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("TRANSFER SECURITY VERIFICATION")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #22d3ee;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(15)
        
        # File information
        file_box = self._create_info_box(
            "FILE INFORMATION",
            f"Filename: {manifest.filename}\n"
            f"Size: {manifest.size:,} bytes ({manifest.size / (1024*1024):.2f} MB)\n"
            f"SHA-256: {manifest.sha256[:32]}...\n"
            f"Scan Status: {manifest.scan_status}\n"
            f"Scan Engine: {manifest.scan_engine}",
            "#3b82f6"
        )
        content_layout.addWidget(file_box)
        
        # Certificate information
        if sender_identity and manifest.sender_certificate:
            from airseal_common.certificates import Certificate
            from datetime import datetime
            import hashlib
            import json
            
            cert = Certificate.from_dict(manifest.sender_certificate)
            
            # Certificate holder
            holder_info = (
                f"Operator Name: {sender_identity.get('operator_name', 'Unknown')}\n"
                f"Organization: {sender_identity.get('organization', 'Unknown')}\n"
                f"Station ID: {sender_identity.get('station_id', 'Unknown')}\n"
            )
            if sender_identity.get('department'):
                holder_info += f"Department: {sender_identity['department']}\n"
            if sender_identity.get('email'):
                holder_info += f"Email: {sender_identity['email']}\n"
            if cert.serial_number:
                holder_info += f"Certificate Serial: {cert.serial_number}\n"
            if cert.public_key_fingerprint:
                holder_info += f"Key Fingerprint: {cert.public_key_fingerprint}\n"
            
            cert_box = self._create_info_box(
                "[VERIFIED] CERTIFICATE HOLDER",
                holder_info.strip(),
                "#10b981"
            )
            content_layout.addWidget(cert_box)
            
            # Certificate authority - handle both old and new formats
            ca_info = ""
            if cert.issuer:
                ca_info = f"CA Name: {cert.issuer.get('common_name', 'Unknown CA')}\n"
                if cert.issuer.get('organization'):
                    ca_info += f"CA Organization: {cert.issuer['organization']}\n"
                if cert.issuer.get('station_id'):
                    ca_info += f"CA Station: {cert.issuer['station_id']}\n"
                issuer_fp = cert.issuer.get('fingerprint') or cert.issuer_fingerprint
                if issuer_fp:
                    ca_info += f"CA Fingerprint: {issuer_fp}\n"
            elif cert.issuer_name:
                ca_info = f"CA Name: {cert.issuer_name}\n"
                if cert.issuer_fingerprint:
                    ca_info += f"CA Fingerprint: {cert.issuer_fingerprint}\n"
            
            ca_box = self._create_info_box(
                "[TRUSTED] CERTIFICATE AUTHORITY (Who Signed)",
                ca_info.strip(),
                "#8b5cf6"
            )
            content_layout.addWidget(ca_box)
            
            # Certificate validity - handle both old and new formats
            if cert.valid_from and cert.valid_until:
                valid_from = datetime.fromisoformat(cert.valid_from.replace('Z', '+00:00'))
                valid_until = datetime.fromisoformat(cert.valid_until.replace('Z', '+00:00'))
                now = datetime.now(valid_from.tzinfo)
            elif cert.not_before and cert.not_after:
                valid_from = datetime.fromtimestamp(cert.not_before)
                valid_until = datetime.fromtimestamp(cert.not_after)
                now = datetime.now()
            else:
                valid_from = datetime.now()
                valid_until = datetime.now()
                now = datetime.now()
            
            days_remaining = (valid_until - now).days
            
            validity_status = "VALID" if days_remaining > 0 else "EXPIRED"
            validity_color = "#10b981" if days_remaining > 30 else "#f59e0b" if days_remaining > 0 else "#ef4444"
            
            # Certificate fingerprint
            cert_bytes = json.dumps(cert.to_dict(), sort_keys=True).encode()
            cert_fingerprint = hashlib.sha256(cert_bytes).hexdigest()
            
            validity_info = (
                f"Status: {validity_status}\n"
                f"Valid From: {valid_from.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Valid Until: {valid_until.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Days Remaining: {days_remaining}\n"
                f"Certificate Fingerprint: {cert_fingerprint[:48]}..."
            )
            
            validity_box = self._create_info_box(
                "CERTIFICATE VALIDITY",
                validity_info,
                validity_color
            )
            content_layout.addWidget(validity_box)
        
        else:
            # No certificate warning
            warning_box = self._create_info_box(
                "[WARNING] NO CERTIFICATE",
                "This transfer does NOT have a verified certificate.\n"
                "Sender identity cannot be cryptographically verified.\n"
                "Only the cryptographic key fingerprint is available.\n\n"
                f"Key Fingerprint: {manifest.signer_id[:48]}...",
                "#f59e0b"
            )
            content_layout.addWidget(warning_box)
        
        # Logged-in user information
        if manifest.user_info:
            user_info = manifest.user_info
            user_text = (
                f"Full Name: {user_info.get('full_name', 'Unknown')}\n"
                f"Username: {user_info.get('username', 'Unknown')}\n"
                f"Role: {user_info.get('role', 'Unknown').upper()}\n"
            )
            if user_info.get('station_id'):
                user_text += f"Station: {user_info['station_id']}\n"
            if user_info.get('organization'):
                user_text += f"Organization: {user_info['organization']}\n"
            if user_info.get('department'):
                user_text += f"Department: {user_info['department']}\n"
            
            # Transfer timestamp
            from datetime import datetime
            timestamp = datetime.fromtimestamp(manifest.timestamp)
            user_text += f"\nTransfer Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            
            user_box = self._create_info_box(
                "[SESSION] USER WHO INITIATED TRANSFER",
                user_text.strip(),
                "#06b6d4"
            )
            content_layout.addWidget(user_box)
        
        # Security checks passed
        checks_box = self._create_info_box(
            "[OK] SECURITY CHECKS PASSED",
            f"- Cryptographic signature verified\n"
            f"- Manifest integrity confirmed\n"
            f"- Policy compliance validated\n"
            f"- Certificate chain verified (if present)\n"
            f"- File scan result: {manifest.scan_status}",
            "#10b981"
        )
        content_layout.addWidget(checks_box)
        
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        
        # Close button
        close_btn = QPushButton("Accept & Continue")
        close_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 14px;
                font-weight: 600;
                padding: 12px 24px;
                min-height: 40px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
        """)
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        # Apply dark theme
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
        """)
        
        dialog.exec()
    
    def _create_info_box(self, title: str, content: str, accent_color: str) -> QLabel:
        """Create a styled information box."""
        box = QLabel(f"<b style='color: {accent_color};'>{title}</b><br><br>{content.replace(chr(10), '<br>')}")
        box.setWordWrap(True)
        box.setStyleSheet(f"""
            QLabel {{
                background: rgba(15, 23, 42, 0.6);
                border-left: 4px solid {accent_color};
                border-radius: 8px;
                padding: 15px;
                color: #e2e8f0;
                font-size: 13px;
                font-family: 'Segoe UI', monospace;
            }}
        """)
        return box
    
    def _prompt_for_media_connection(self) -> None:
        """Instruct the operator to connect removable media after trust is established."""
        filename = self.manifest["filename"] if self.manifest else "the file"
        self.result_label.setText(
            f"Manifest verified for {filename}.\n"
            "Connect the trusted USB/CD now and proceed with file verification."
        )

    def _is_removable_media(self, path: Path) -> bool:
        """Return True when the path resolves to removable or optical media."""
        try:
            drive = path.drive or path.anchor
            if not drive:
                return False

            import ctypes  # Local import to avoid platform issues

            DRIVE_REMOVABLE = 2
            DRIVE_CDROM = 5
            if not hasattr(ctypes, "windll"):
                return True
            normalized = drive.rstrip("\\/") + "\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(normalized)
            return drive_type in (DRIVE_REMOVABLE, DRIVE_CDROM)
        except Exception:
            return False


def main():
    """Entry point for the receiver application."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = ReceiverMainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
