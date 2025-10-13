"""AirSeal Receiver - Professional Desktop Application."""

from __future__ import annotations

import sys
import time
import json
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
        self.status_label = QLabel("Scanning... Point camera at QR code")
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
            self.status_label.setText("✓ Camera active - scanning for QR codes...")
        except Exception as e:
            self.status_label.setText(f"✗ Camera error: {str(e)}")
            self.status_label.setStyleSheet("color: #ef4444; font-size: 13px; padding: 8px;")
            self.timer.stop()
    
    def _scan_frame(self):
        """Capture and scan a frame with enhanced tolerance for low-quality webcams."""
        if not self.camera_active:
            return

        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            import numpy as np

            ret, frame = self.cap.read()
            if not ret:
                return

            display_frame = frame.copy()

            gray = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2GRAY)
            denoised = self.cv2.bilateralFilter(gray, 7, 75, 75)
            clahe = self.cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
            enhanced = clahe.apply(denoised)

            decoded_text = None
            polygon_points: Optional[list[tuple[int, int]]] = None

            decoded_objects = pyzbar_decode(enhanced) or pyzbar_decode(gray)
            if decoded_objects:
                obj = decoded_objects[0]
                decoded_text = obj.data.decode("utf-8")
                if obj.polygon:
                    polygon_points = [(int(p.x), int(p.y)) for p in obj.polygon]
            else:
                if self._qr_detector is None:
                    self._qr_detector = self.cv2.QRCodeDetector()

                data, points, _ = self._qr_detector.detectAndDecode(enhanced)
                if data:
                    decoded_text = data
                    if points is not None and points.size:
                        reshaped = points.reshape(-1, 2)
                        polygon_points = [(int(pt[0]), int(pt[1])) for pt in reshaped]

            if polygon_points:
                pts = np.array(polygon_points, dtype=np.int32)
                self.cv2.polylines(display_frame, [pts], True, (0, 255, 0), 3)
                centroid = pts.mean(axis=0).astype(int)
                self.cv2.circle(display_frame, tuple(centroid), 6, (0, 255, 0), -1)

            if decoded_text:
                self.qr_data = decoded_text
                self.cv2.putText(
                    display_frame,
                    "QR code locked",
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

                self.status_label.setText("✓ QR code detected!")
                self.status_label.setStyleSheet("color: #22d3ee; font-size: 14px; font-weight: bold; padding: 8px;")

                self.timer.stop()
                QTimer.singleShot(350, self.accept)
                return

            h, w, _ = display_frame.shape
            guide_margin = int(min(h, w) * 0.18)
            self.cv2.rectangle(
                display_frame,
                (guide_margin, guide_margin),
                (w - guide_margin, h - guide_margin),
                (34, 211, 238),
                2,
            )

            sweep_min = guide_margin + 12
            sweep_max = h - guide_margin - 12
            if sweep_max <= sweep_min:
                sweep_min = guide_margin
                sweep_max = h - guide_margin - 1
            span = max(sweep_max - sweep_min, 1)
            step = max(int(span * 0.05), 2)
            self._scan_phase += self._scan_direction * step
            if self._scan_phase >= span:
                self._scan_phase = span
                self._scan_direction = -1
            elif self._scan_phase <= 0:
                self._scan_phase = 0
                self._scan_direction = 1
            sweep_y = int(sweep_min + self._scan_phase)
            self.cv2.line(
                display_frame,
                (guide_margin + 6, sweep_y),
                (w - guide_margin - 6, sweep_y),
                (14, 165, 233),
                2,
            )
            self.cv2.line(
                display_frame,
                (guide_margin + 6, sweep_y + 3),
                (w - guide_margin - 6, sweep_y + 3),
                (34, 211, 238),
                1,
            )

            self.cv2.putText(
                display_frame,
                "Align QR inside the blue guide",
                (20, h - 40),
                self.cv2.FONT_HERSHEY_SIMPLEX,
                0.75,
                (148, 163, 184),
                2,
                self.cv2.LINE_AA,
            )
            self.status_label.setText("Scanning… hold steady for instant lock")
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
                
                self.progress.emit("✓ QR code decoded")
                
                # Parse manifest
                manifest_qr = ManifestQRData.from_json(qr_data)
                manifest_dict = manifest_qr.get_manifest_dict()
                
                # Convert to Manifest object
                manifest = Manifest(**manifest_dict)
                
                self.progress.emit("✓ Manifest parsed")
            
            # Verify signature and nonce
            self.progress.emit("Verifying signature...")
            success, error = self.verifier.verify_manifest(manifest, check_nonce=False)
            
            if not success:
                raise ValueError(f"Signature verification failed: {error}")
            
            self.progress.emit("✓ Signature valid")
            
            # Check policy
            self.progress.emit("Checking policy...")
            engine = self.policy_store.get_engine(manifest.policy_id)
            
            if not engine:
                raise ValueError(f"Unknown policy: {manifest.policy_id}")
            
            complies, reason = engine.check_manifest(manifest)
            
            if not complies:
                raise ValueError(f"Policy violation: {reason}")
            
            self.progress.emit("✓ Policy check passed")
            
            # Success
            self.finished.emit({
                "success": True,
                "manifest": asdict(manifest),
                "error": None,
            })
            
        except Exception as e:
            self.progress.emit(f"✗ Error: {str(e)}")
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
            self.progress.emit(f"✓ Hash: {actual_hash[:16]}...")
            
            # Compare with manifest
            self.progress.emit("Comparing with manifest...")
            expected_hash = self.manifest["sha256"]
            
            if actual_hash != expected_hash:
                raise ValueError(
                    f"Hash mismatch!\nExpected: {expected_hash[:16]}...\nActual: {actual_hash[:16]}..."
                )
            
            self.progress.emit("✓ Hash matches manifest")

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
            self.progress.emit(f"✓ Antivirus scan complete ({scan_result.engine})")

            # Check policy on actual file
            self.progress.emit("Checking file policy...")
            engine = self.policy_store.get_engine(self.manifest["policy_id"])
            
            if engine:
                safe, reason = engine.check_file(self.file_path)
                if not safe:
                    raise ValueError(f"File policy check failed: {reason}")
            
            self.progress.emit("✓ File passes policy checks")
            
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
            
            self.progress.emit(f"✓ Receipt saved: {receipt_path.name}")
            
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
            })
            
        except Exception as e:
            self.progress.emit(f"✗ Error: {str(e)}")
            self.finished.emit({
                "success": False,
                "result": "",
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
        from shared_keys import get_or_create_receiver_key, get_or_create_sender_key
        
        self.receiver_key = get_or_create_receiver_key()
        self.receiver_fingerprint = self.receiver_key.get_fingerprint()
        self.trust_store = TrustStore()
        self.nonce_mgr = NonceManager()
        self.policy_store = PolicyStore()
        
        # For testing: Add sender's public key to trust store
        # In production, this would be done through secure key exchange
        sender_key = get_or_create_sender_key()
        self.trust_store.add_key(
            key_id=sender_key.get_fingerprint(),
            public_key=sender_key.public_key
        )
        print(f"✓ Receiver trusts sender: {sender_key.get_fingerprint()[:16]}...")
        
        # State
        self.manifest: Optional[dict] = None
        self._manifest_verified_at: Optional[float] = None
        
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
        self.scan_camera_btn.setIcon(self.style().standardIcon(QStyle.SP_DesktopIcon))
        self.scan_camera_btn.clicked.connect(self._scan_with_camera)
        btn_row.addWidget(self.scan_camera_btn)

        self.scan_file_btn = QPushButton("Load QR from File")
        self.scan_file_btn.setEnabled(True)  # Ready to scan immediately
        self.scan_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.scan_file_btn.setStyleSheet(self._primary_button_style())
        self.scan_file_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
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

        self.select_file_btn = QPushButton("Select File to Verify")
        self.select_file_btn.setEnabled(False)
        self.select_file_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.select_file_btn.setStyleSheet(self._primary_button_style())
        self.select_file_btn.setIcon(self.style().standardIcon(QStyle.SP_FileIcon))
        self.select_file_btn.clicked.connect(self._select_file_to_verify)
        layout.addWidget(self.select_file_btn)

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
            
            self._append_and_scroll(self.manifest_status, "✓ Manifest parsed successfully")
            
            # Verify signature
            self._append_and_scroll(self.manifest_status, "[INFO] Verifying digital signature...")
            verifier = ManifestVerifier(self.trust_store, self.nonce_mgr)
            success, error = verifier.verify_manifest(manifest, check_nonce=False)
            
            if not success:
                raise ValueError(f"Signature verification failed: {error}")
            
            self._append_and_scroll(self.manifest_status, "✓ Signature verified")
            
            # Check policy
            self._append_and_scroll(self.manifest_status, "[INFO] Checking security policy...")
            engine = self.policy_store.get_engine(manifest.policy_id)
            
            if not engine:
                raise ValueError(f"Unknown policy: {manifest.policy_id}")
            
            complies, reason = engine.check_manifest(manifest)
            
            if not complies:
                raise ValueError(f"Policy violation: {reason}")
            
            self._append_and_scroll(self.manifest_status, "✓ Policy check passed")
            
            # Success - store manifest and enable file verification
            self.manifest = asdict(manifest)
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
            
            QMessageBox.information(
                self,
                "QR Code Scanned Successfully",
                f"Manifest verified!\n\nFile: {self.manifest['filename']}\n"
                f"Size: {self.manifest['size']} bytes\n\n"
                "Connect the trusted USB/CD now, then choose 'Select File to Verify'."
            )
            
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
            engine = result.get("scan_engine", "Antivirus")
            QMessageBox.information(
                self,
                "Success",
                f"File verified and imported successfully!\n\nAntivirus engine: {engine}"
            )
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
