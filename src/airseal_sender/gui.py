from __future__ import annotations

import sys
import time
import json
from pathlib import Path
from typing import Optional
from dataclasses import asdict

from PySide6.QtCore import Qt, QThread, Signal, QTime
from PySide6.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont, QIcon, QAction, QTextCursor, QPixmap
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
    QScrollArea,
    QStyle,
    QToolBar,
)

# Import AirSeal backend
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from airseal_common import (
    KeyPair,
    Manifest,
    ManifestSigner,
    ScannerFactory,
    QRCodeGenerator,
    ManifestQRData,
    compute_file_hash,
)


def _find_logo_path() -> Optional[Path]:
    """Return the first matching logo file irrespective of case/extension."""
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
    """Load the shared application icon if available."""
    logo_path = _find_logo_path()
    if logo_path:
        icon = QIcon(str(logo_path))
        if not icon.isNull():
            return icon
    return QIcon()


def _load_logo_pixmap(max_size: int = 72) -> Optional[QPixmap]:
    """Load and scale the shared logo for in-window display."""
    logo_path = _find_logo_path()
    if not logo_path:
        return None

    pixmap = QPixmap(str(logo_path))
    if pixmap.isNull():
        return None

    if pixmap.width() > max_size:
        pixmap = pixmap.scaledToWidth(max_size, Qt.TransformationMode.SmoothTransformation)
    return pixmap


class ScanWorker(QThread):
    """Background worker for file analysis with real backend integration."""

    progress = Signal(str)
    progress_value = Signal(int)
    finished = Signal(dict)

    def __init__(self, source: Path, sender_key: KeyPair, nonce: str, transfer_id: str, certificate: Optional[dict] = None, user_info: Optional[dict] = None) -> None:
        super().__init__()
        self._source = source
        self._sender_key = sender_key
        self._nonce = nonce
        self._transfer_id = transfer_id
        self._certificate = certificate
        self._user_info = user_info

    def run(self) -> None:
        """Execute real analysis pipeline with backend."""
        try:
            # Step 1: Hash file
            self.progress.emit("Computing SHA-256 hash...")
            self.progress_value.emit(20)
            file_hash = compute_file_hash(self._source)
            self.progress.emit(f"[OK] Hash: {file_hash[:16]}...")
            
            # Step 2: Scan file
            self.progress.emit("Scanning file for threats...")
            self.progress_value.emit(40)
            scanner = ScannerFactory.get_scanner("auto")
            engine_name = getattr(scanner, "engine_name", "Unknown")
            if engine_name.lower() == "demo scanner":
                self.finished.emit({
                    "success": False,
                    "error": (
                        "Trusted antivirus engine not available. Install Windows Defender or "
                        "ClamAV on the sender workstation and retry."
                    ),
                })
                return

            scan_result = scanner.scan(self._source)
            self.progress.emit(f"[OK] Scan: {scan_result.status} ({scan_result.engine})")
            
            if not scan_result.is_clean():
                self.finished.emit({
                    "success": False,
                    "error": f"File infected: {', '.join(scan_result.threats_found)}"
                })
                return
            
            # Step 3: Create manifest
            self.progress.emit("Building manifest...")
            self.progress_value.emit(60)
            manifest = Manifest(
                filename=self._source.name,
                size=self._source.stat().st_size,
                sha256=file_hash,
                scan_status=scan_result.status,
                scan_engine=scan_result.engine,
                scan_details=scan_result.details,
                timestamp=time.time(),
                signer_id=self._sender_key.get_fingerprint(),
                policy_id="default-v1",
                nonce=self._nonce,
                transfer_id=self._transfer_id,
                sender_certificate=self._certificate,
                user_info=self._user_info,
            )
            if self._certificate and self._user_info:
                self.progress.emit(f"[OK] Manifest created (authenticated: {self._user_info.get('full_name', 'Unknown')})")
            elif self._certificate:
                self.progress.emit(f"[OK] Manifest created (with certificate)")
            else:
                self.progress.emit("[OK] Manifest created")
            
            # Step 4: Sign manifest
            self.progress.emit("Signing with Ed25519...")
            self.progress_value.emit(80)
            signer = ManifestSigner(self._sender_key)
            signed_manifest = signer.sign_manifest(manifest)
            self.progress.emit(f"[OK] Signature: {signed_manifest.signature[:16]}...")
            
            # Step 5: Generate QR code
            self.progress.emit("Generating QR code...")
            self.progress_value.emit(95)
            manifest_json = json.dumps(asdict(signed_manifest), separators=(',', ':'))
            qr_generator = QRCodeGenerator()
            manifest_qr = ManifestQRData(manifest_json)
            qr_img = qr_generator.generate(manifest_qr.to_json(), box_size=8, border=2)
            
            # Convert PIL image to QPixmap
            from io import BytesIO
            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            qr_pixmap = QPixmap()
            qr_pixmap.loadFromData(buffer.getvalue())
            
            self.progress.emit("[OK] QR code generated")
            self.progress_value.emit(100)
            
            # Return result
            result = {
                "success": True,
                "manifest": asdict(signed_manifest),
                "qr_pixmap": qr_pixmap,
                "file_hash": file_hash,
                "scan_result": scan_result,
            }
            self.finished.emit(result)
            
        except Exception as e:
            self.finished.emit({"success": False, "error": f"Analysis failed: {str(e)}"})


class SenderMainWindow(QMainWindow):
    """Professional sender console with improved UX and accessibility."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AirSeal Sender")
        self.resize(1200, 820)

        app_icon = _load_app_icon()
        if not app_icon.isNull():
            self.setWindowIcon(app_icon)
        else:
            self.setWindowIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))

        # User authentication
        self.logged_in_user = None
        self._perform_login()
        
        if not self.logged_in_user:
            # Login failed or cancelled - exit
            sys.exit(0)
        
        self.selected_file: Optional[Path] = None
        self.manifest: Optional[dict] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.qr_pixmap: Optional[QPixmap] = None
        
        # Initialize sender key using shared key storage for testing
        from shared_keys import get_or_create_sender_key
        username = getattr(self.logged_in_user, "username", None)
        self.sender_key = get_or_create_sender_key(username)
        self.sender_fingerprint = self.sender_key.get_fingerprint()
        
        # Load sender certificate (if available)
        self.certificate_path: Optional[Path] = None
        self.sender_certificate = self._load_certificate()
        
        # Nonce data (to be scanned from receiver)
        self.nonce: Optional[str] = None
        self.transfer_id: Optional[str] = None

        self._build_ui()
        
        # Update window title with logged-in user
        self.setWindowTitle(f"AirSeal Sender - {self.logged_in_user.full_name} ({self.logged_in_user.role.capitalize()})")

    def _build_ui(self) -> None:
        """Build main UI with global scroll area and toolbar."""

        # Toolbar (accessible actions)
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        toolbar.setIconSize(toolbar.iconSize())  # keep defaults
        self.addToolBar(Qt.TopToolBarArea, toolbar)

        action_open = QAction(self.style().standardIcon(QStyle.SP_DialogOpenButton), "Open file…", self)
        action_open.setShortcut("Ctrl+O")
        action_open.triggered.connect(self._open_file_dialog)
        toolbar.addAction(action_open)

        toolbar.addSeparator()

        action_reset = QAction(self.style().standardIcon(QStyle.SP_BrowserReload), "Reset", self)
        action_reset.setShortcut("Ctrl+R")
        action_reset.triggered.connect(self._reset_session)
        toolbar.addAction(action_reset)

        toolbar.addSeparator()

        action_about = QAction("About", self)
        action_about.triggered.connect(self._show_about)
        toolbar.addAction(action_about)
        
        toolbar.addSeparator()
        
        # Admin menu (only for admins)
        if self.logged_in_user and self.logged_in_user.role == "admin":
            action_users = QAction("👥 Manage Users", self)
            action_users.triggered.connect(self._manage_users)
            toolbar.addAction(action_users)
            
            action_gen_cert = QAction("📜 Generate Certificate", self)
            action_gen_cert.triggered.connect(self._generate_certificate)
            toolbar.addAction(action_gen_cert)

        # Background pane + global scroll
        background = QWidget()
        background.setObjectName("backgroundPane")
        background.setStyleSheet(
            """
            QWidget#backgroundPane {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0b1120, stop:1 #111c36);
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            """
        )
        background_layout = QVBoxLayout(background)
        background_layout.setContentsMargins(0, 0, 0, 0)
        background_layout.setSpacing(0)

        # Scroll container
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        background_layout.addWidget(scroll)

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(44, 24, 44, 36)
        container_layout.setSpacing(24)
        scroll.setWidget(container)

        # Header with logo
        header_row = QHBoxLayout()
        header_row.setSpacing(18)
        header_row.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        container_layout.addLayout(header_row)

        logo_pix = _load_logo_pixmap()
        if logo_pix is not None:
            logo_label = QLabel()
            logo_label.setPixmap(logo_pix)
            logo_label.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            header_row.addWidget(logo_label)

        header = QLabel("AirSeal Sender Console")
        header.setFont(QFont("Segoe UI", 26, QFont.Weight.Bold))
        header_row.addWidget(header)
        header_row.addStretch()

        subheader = QLabel("Prepare a signed manifest for controlled, air-gapped transfer.")
        subheader.setStyleSheet("color: #94a3b8; font-size: 15px; letter-spacing: 0.3px;")
        container_layout.addWidget(subheader)
        
        # User info panel
        user_info_frame = QFrame()
        user_info_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(34, 211, 238, 0.15), stop:1 rgba(14, 165, 233, 0.15));
                border: 1px solid rgba(34, 211, 238, 0.3);
                border-radius: 12px;
                padding: 12px;
            }
        """)
        user_info_layout = QHBoxLayout(user_info_frame)
        user_info_layout.setSpacing(15)
        
        user_icon = QLabel("[USER]")
        user_icon.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        user_icon.setStyleSheet("color: #22d3ee;")
        user_info_layout.addWidget(user_icon)
        
        user_details = QLabel(
            f"<b>{self.logged_in_user.full_name}</b><br>"
            f"<span style='color: #22d3ee;'>{self.logged_in_user.role.upper()}</span> • "
            f"{self.logged_in_user.username}"
        )
        user_details.setStyleSheet("color: #f8fafc; font-size: 13px;")
        user_info_layout.addWidget(user_details)
        
        if self.logged_in_user.station_id:
            station_label = QLabel(f"Station: {self.logged_in_user.station_id}")
            station_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
            user_info_layout.addWidget(station_label)
        
        user_info_layout.addStretch()
        
        container_layout.addWidget(user_info_frame)

        # Cards
        self.file_card = self._create_card(
            "1. Source selection",
            "Identify the artefact for transfer and capture metadata.",
        )
        container_layout.addWidget(self.file_card)
        self._init_file_card()

        self.analysis_card = self._create_card(
            "2. Analysis & signing",
            "Integrity checks, threat evaluation, and cryptographic signing.",
        )
        container_layout.addWidget(self.analysis_card)
        self._init_analysis_card()

        self.delivery_card = self._create_card(
            "3. Transfer package",
            "Display the manifest summary and QR payload.",
        )
        container_layout.addWidget(self.delivery_card)
        self._init_delivery_card()

        container_layout.addStretch()

        # Set central
        self.setCentralWidget(background)

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

    def _init_file_card(self) -> None:
        """Initialize file selection card."""
        layout = self.file_card.layout()

        drop_zone = QLabel("Drop a file or choose from disk")
        drop_zone.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_zone.setMinimumHeight(170)
        drop_zone.setObjectName("dropZone")
        drop_zone.setAcceptDrops(True)
        drop_zone.setFocusPolicy(Qt.StrongFocus)
        drop_zone.setToolTip("Drop a file here or press Enter/Space to browse")
        drop_zone.dragEnterEvent = self._drag_enter_event
        drop_zone.dropEvent = self._drop_event
        drop_zone.mousePressEvent = lambda e: self._open_file_dialog()
        drop_zone.keyPressEvent = lambda e: self._open_file_dialog() if e.key() in (Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space) else None
        drop_zone.setStyleSheet(
            """
            QLabel#dropZone {
                border: 2px dashed #38bdf8;
                border-radius: 16px;
                background: rgba(8, 47, 73, 0.45);
                color: #38bdf8;
                font-size: 16px;
                font-weight: 600;
            }
            QLabel#dropZone[fileSelected="true"] {
                border: 2px solid #22c55e;
                background: rgba(22, 101, 52, 0.40);
                color: #86efac;
            }
            """
        )
        layout.addWidget(drop_zone)
        self.drop_zone = drop_zone

        row = QHBoxLayout()
        row.setSpacing(12)
        layout.addLayout(row)

        meta = QLabel("No file selected")
        meta.setWordWrap(True)
        meta.setStyleSheet("color: #cbd5f5;")
        meta.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        row.addWidget(meta)
        self.file_meta_label = meta

        browse_btn = QPushButton("Browse")
        browse_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        browse_btn.setStyleSheet(self._primary_button_style())
        browse_btn.clicked.connect(self._open_file_dialog)
        browse_btn.setToolTip("Select a file from disk")
        row.addWidget(browse_btn)

    def _init_analysis_card(self) -> None:
        """Initialize analysis card."""
        layout = self.analysis_card.layout()

        log_view = QTextEdit()
        log_view.setReadOnly(True)
        log_view.setMinimumHeight(200)
        log_view.setToolTip("Analysis log output")
        log_view.setStyleSheet(
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
        layout.addWidget(log_view)
        self.log_view = log_view

        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(0)
        progress.setTextVisible(True)
        progress.setFormat("%p% complete")
        progress.setStyleSheet(
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
        layout.addWidget(progress)
        self.progress_bar = progress

        controls = QHBoxLayout()
        controls.setSpacing(12)
        layout.addLayout(controls)
        controls.addStretch()

        scan_btn = QPushButton("Start analysis")
        scan_btn.setEnabled(False)
        scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        scan_btn.setStyleSheet(self._primary_button_style())
        scan_btn.clicked.connect(self._start_scan)
        scan_btn.setToolTip("Begin analysis pipeline on the selected file")
        controls.addWidget(scan_btn)
        self.scan_btn = scan_btn

        reset_btn = QPushButton("Reset")
        reset_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reset_btn.setStyleSheet(self._secondary_button_style())
        reset_btn.clicked.connect(self._reset_session)
        reset_btn.setToolTip("Clear the session and start over")
        controls.addWidget(reset_btn)

        clear_log_btn = QPushButton("Clear log")
        clear_log_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_log_btn.setStyleSheet(self._secondary_button_style())
        clear_log_btn.clicked.connect(self._clear_log)
        clear_log_btn.setToolTip("Clear analysis logs")
        controls.addWidget(clear_log_btn)

    def _init_delivery_card(self) -> None:
        """Initialize delivery card."""
        layout = self.delivery_card.layout()

        row = QHBoxLayout()
        row.setSpacing(24)
        layout.addLayout(row)

        qr_label = QLabel("QR output pending")
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_label.setMinimumSize(270, 270)
        qr_label.setStyleSheet(
            """
            QLabel {
                background: rgba(8, 47, 73, 0.4);
                border: 1px dashed rgba(148, 163, 184, 0.35);
                border-radius: 16px;
                color: #94a3b8;
                font-size: 14px;
                letter-spacing: 0.8px;
            }
            """
        )
        row.addWidget(qr_label, 1)
        self.qr_label = qr_label

        summary_column = QVBoxLayout()
        summary_column.setSpacing(12)
        row.addLayout(summary_column, 2)

        summary_label = QLabel("Manifest summary will appear after analysis completes.")
        summary_label.setWordWrap(True)
        summary_label.setStyleSheet("color: #cbd5f5; font-size: 14px; line-height: 1.6;")
        summary_column.addWidget(summary_label)
        self.summary_label = summary_label

        actions_row = QHBoxLayout()
        actions_row.setSpacing(12)
        summary_column.addLayout(actions_row)

        copy_hash_btn = QPushButton("Copy SHA-256")
        copy_hash_btn.setEnabled(False)
        copy_hash_btn.setStyleSheet(self._secondary_button_style())
        copy_hash_btn.clicked.connect(self._copy_sha256)
        copy_hash_btn.setToolTip("Copy the computed SHA-256 hash to clipboard")
        actions_row.addWidget(copy_hash_btn)
        self.copy_hash_btn = copy_hash_btn

        save_manifest_btn = QPushButton("Save manifest…")
        save_manifest_btn.setEnabled(False)
        save_manifest_btn.setStyleSheet(self._primary_button_style())
        save_manifest_btn.clicked.connect(self._save_manifest)
        save_manifest_btn.setToolTip("Save the manifest as a JSON file")
        actions_row.addWidget(save_manifest_btn)
        self.save_manifest_btn = save_manifest_btn

        # Add Copy Manifest JSON action for quick sharing
        copy_manifest_btn = QPushButton("Copy manifest JSON")
        copy_manifest_btn.setEnabled(False)
        copy_manifest_btn.setStyleSheet(self._secondary_button_style())
        copy_manifest_btn.clicked.connect(self._copy_manifest_json)
        copy_manifest_btn.setToolTip("Copy the full manifest JSON to clipboard")
        actions_row.addWidget(copy_manifest_btn)
        self.copy_manifest_btn = copy_manifest_btn

        self.delivery_card.setEnabled(False)

    def _show_about(self) -> None:
        QMessageBox.information(
            self,
            "About AirSeal Sender",
            "AirSeal Sender\n\nA professional console for preparing signed manifests "
            "for air-gapped transfer. Includes integrity hashing, simulated threat scan, "
            "and signing pipeline with a focus on usability and clarity.",
        )

    def _drag_enter_event(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def _drop_event(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        if urls:
            candidate = Path(urls[0].toLocalFile())
            if candidate.is_file():
                self._load_file(candidate)
            else:
                QMessageBox.warning(self, "Invalid item", "Please drop a file, not a folder.")

    def _open_file_dialog(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(self, "Select file", "", "All Files (*.*)")
        if file_path:
            self._load_file(Path(file_path))

    def _load_file(self, file_path: Path) -> None:
        try:
            self.selected_file = file_path
            self.manifest = None

            size_mb = file_path.stat().st_size / (1024 * 1024)
            self.file_meta_label.setText(
                f"<b>{file_path.name}</b> — {size_mb:.2f} MB<br><small>{file_path.parent}</small>"
            )
            self.drop_zone.setProperty("fileSelected", "true")
            self.drop_zone.setText(file_path.name)
            self.drop_zone.style().unpolish(self.drop_zone)
            self.drop_zone.style().polish(self.drop_zone)

            self.log_view.clear()
            self.progress_bar.setValue(0)
            self.scan_btn.setEnabled(True)
            self.delivery_card.setEnabled(False)
            self.summary_label.setText("Manifest summary will appear after analysis completes.")
            self.qr_label.setText("QR output pending")
            self.copy_hash_btn.setEnabled(False)
            self.save_manifest_btn.setEnabled(False)
            self.copy_manifest_btn.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Load failed", f"Could not load file metadata:\n{e}")

    def _start_scan(self) -> None:
        if not self.selected_file:
            QMessageBox.warning(self, "No file", "Select a source file first.")
            return
        
        # SECURITY CHECK: Validate sender identity and certificate before transfer
        validation_result = self._validate_sender_identity()
        if not validation_result["valid"]:
            QMessageBox.critical(
                self,
                "Transfer Blocked",
                f"Cannot proceed with transfer:\n\n{validation_result['error']}\n\n"
                f"Please contact your administrator to resolve this issue."
            )
            return
        
        # Show identity confirmation dialog
        if not self._confirm_sender_identity(validation_result):
            self.statusBar().showMessage("Transfer cancelled by user", 3000)
            return
        
        # Generate nonce for this transfer
        if not self.nonce:
            import secrets
            self.nonce = secrets.token_hex(32)
            self.transfer_id = secrets.token_hex(16)

        self.scan_btn.setEnabled(False)
        self.log_view.clear()
        self.progress_bar.setValue(0)

        # Prepare user info for manifest
        user_info = {
            "username": self.logged_in_user.username,
            "full_name": self.logged_in_user.full_name,
            "role": self.logged_in_user.role,
            "station_id": self.logged_in_user.station_id,
            "organization": self.logged_in_user.organization,
            "department": self.logged_in_user.department,
        } if self.logged_in_user else None

        worker = ScanWorker(self.selected_file, self.sender_key, self.nonce, self.transfer_id, self.sender_certificate, user_info)
        worker.progress.connect(self._append_log)
        worker.progress_value.connect(self.progress_bar.setValue)
        worker.finished.connect(self._scan_complete)
        worker.finished.connect(worker.deleteLater)
        self.scan_worker = worker
        worker.start()

    def _append_log(self, message: str) -> None:
        timestamp = QTime.currentTime().toString("HH:mm:ss")
        self.log_view.append(f"[{timestamp}] {message}")
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def _scan_complete(self, result: dict) -> None:
        if result.get("success"):
            self.manifest = result["manifest"]
            self.qr_pixmap = result.get("qr_pixmap")
            manifest = result["manifest"]
            size_mb = manifest["size"] / (1024 * 1024)
            self.log_view.append("[OK] Analysis pipeline completed successfully.")
            
            # Display QR code
            if self.qr_pixmap:
                scaled_pixmap = self.qr_pixmap.scaled(
                    300, 300,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                self.qr_label.setPixmap(scaled_pixmap)
            
            self.summary_label.setText(
                "<b>Manifest summary</b><br>"
                f"File: {manifest['filename']}<br>"
                f"Size: {size_mb:.2f} MB<br>"
                f"SHA-256: <code>{manifest['sha256'][:16]}...</code><br>"
                f"Scan: {manifest['scan_status']} ({manifest['scan_engine']})<br>"
                f"Signature: <code>{manifest['signature'][:16]}...</code><br>"
                f"Signer: {self.sender_fingerprint}"
            )
            self.delivery_card.setEnabled(True)
            self.copy_hash_btn.setEnabled(True)
            self.save_manifest_btn.setEnabled(True)
            self.copy_manifest_btn.setEnabled(True)
        else:
            self.log_view.append(f"✗ Error: {result.get('error', 'Unknown failure')}")
            QMessageBox.critical(self, "Analysis failed", result.get("error", "Unknown failure"))

        self.scan_btn.setEnabled(True)

    def _copy_sha256(self) -> None:
        if not self.manifest:
            return
        QApplication.clipboard().setText(self.manifest.get("sha256", ""))
        self.statusBar().showMessage("SHA-256 copied to clipboard", 3000)

    def _save_manifest(self) -> None:
        if not self.manifest:
            return
        default_name = f"{self.manifest.get('filename','manifest')}.manifest.json"
        path, _ = QFileDialog.getSaveFileName(self, "Save manifest", default_name, "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.manifest, f, indent=2)
            self.statusBar().showMessage("Manifest saved", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", f"Could not save manifest:\n{e}")

    def _copy_manifest_json(self) -> None:
        if not self.manifest:
            return
        try:
            json_text = json.dumps(self.manifest, indent=2)
            QApplication.clipboard().setText(json_text)
            self.statusBar().showMessage("Manifest JSON copied", 3000)
        except Exception as e:
            QMessageBox.critical(self, "Copy failed", f"Could not copy manifest JSON:\n{e}")

    def _perform_login(self):
        """Perform user login."""
        from airseal_common.admin_dialogs import LoginDialog
        
        login_dialog = LoginDialog(self)
        if login_dialog.exec() == QDialog.DialogCode.Accepted:
            self.logged_in_user = login_dialog.authenticated_user
            print(f"[OK] User logged in: {self.logged_in_user.full_name} ({self.logged_in_user.role})")
        else:
            self.logged_in_user = None
    
    def _manage_users(self):
        """Open user management dialog (admin only)."""
        if self.logged_in_user.role != "admin":
            QMessageBox.warning(self, "Access Denied", "Only administrators can manage users")
            return
        
        from airseal_common.admin_dialogs import UserManagementDialog
        dialog = UserManagementDialog(self.logged_in_user, self)
        dialog.exec()
    
    def _generate_certificate(self):
        """Generate certificate for a user (admin only)."""
        if self.logged_in_user.role != "admin":
            QMessageBox.warning(self, "Access Denied", "Only administrators can generate certificates")
            return
        
        from airseal_common.admin_dialogs import CertificateGenerationDialog
        
        dialog = CertificateGenerationDialog(self.logged_in_user, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Certificate was generated successfully
            QMessageBox.information(
                self,
                "Success",
                "Certificate generated successfully!\n\n"
                "The operator can now use this certificate for secure transfers."
            )
    
    def _validate_sender_identity(self) -> dict:
        """
        Validate sender identity and certificate before allowing transfer.
        
        Returns dict with:
        - valid: bool
        - error: str (if not valid)
        - certificate_status: str
        - identity: dict (if certificate available)
        - signed_by: str (CA name)
        """
        result = {
            "valid": False,
            "error": None,
            "certificate_status": "No certificate",
            "identity": None,
            "signed_by": None,
            "expires": None
        }
        
        # Check if user is logged in
        if not self.logged_in_user:
            result["error"] = "No user logged in. Please restart the application."
            return result
        
        # Check if certificate exists
        if not self.sender_certificate:
            result["certificate_status"] = "WARNING: No certificate (anonymous transfer)"
            result["valid"] = True  # Allow but warn
            result["error"] = None
            return result
        
        # Validate certificate
        try:
            from airseal_common.certificates import Certificate, CertificateVerifier
            from pathlib import Path
            from datetime import datetime
            
            cert = Certificate.from_dict(self.sender_certificate)
            
            # Load CA certificate for validation
            ca_path = Path("test_certificates/ca_certificate.json")
            if not ca_path.exists():
                result["error"] = "Certificate Authority (CA) certificate not found.\nCannot verify certificate authenticity."
                return result
            
            import json
            with open(ca_path, 'r', encoding='utf-8') as f:
                ca_cert_data = json.load(f)

            # Verify certificate
            verifier = CertificateVerifier(ca_cert_data)
            is_valid, error_msg = verifier.verify_certificate(cert)
            
            if not is_valid:
                result["error"] = f"Certificate validation failed:\n{error_msg}\n\nTransfer cannot proceed with invalid certificate."
                return result
            
            # Check expiration
            valid_until = datetime.fromisoformat(cert.valid_until.replace('Z', '+00:00'))
            now = datetime.now(valid_until.tzinfo)
            
            if now > valid_until:
                result["error"] = f"Certificate has EXPIRED on {valid_until.strftime('%Y-%m-%d')}.\n\nPlease request a new certificate from your administrator."
                return result
            
            days_until_expiry = (valid_until - now).days
            if days_until_expiry <= 30:
                result["certificate_status"] = f"WARNING: Certificate expires in {days_until_expiry} days"
            else:
                result["certificate_status"] = "Valid"
            
            # Extract identity
            result["identity"] = verifier.extract_identity(cert)
            issuer_info = cert.issuer or {}
            result["signed_by"] = issuer_info.get("common_name", cert.issuer_name or "Unknown CA")
            result["issuer_fingerprint"] = issuer_info.get("fingerprint") or cert.issuer_fingerprint
            result["serial"] = cert.serial_number
            result["valid_from"] = cert.valid_from
            result["expires"] = valid_until.strftime("%Y-%m-%d %H:%M:%S")
            result["valid"] = True
            
        except Exception as e:
            result["error"] = f"Certificate validation error:\n{str(e)}\n\nPlease contact your administrator."
            return result
        
        return result
    
    def _confirm_sender_identity(self, validation_result: dict) -> bool:
        """
        Show confirmation dialog with sender identity before transfer.
        Returns True if user confirms, False if cancelled.
        """
        from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox
        from PySide6.QtGui import QFont
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Confirm Sender Identity")
        dialog.setMinimumWidth(600)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("CONFIRM SENDER IDENTITY BEFORE TRANSFER")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #22d3ee;")
        layout.addWidget(title)
        
        # Warning if no certificate
        if not validation_result.get("identity"):
            warning = QLabel(
                "[WARNING] No certificate attached to this transfer.\n"
                "The receiver will only see your cryptographic key fingerprint.\n\n"
                "Consider requesting a certificate from your administrator for verified identity."
            )
            warning.setWordWrap(True)
            warning.setStyleSheet("""
                background: rgba(234, 179, 8, 0.1);
                border: 2px solid rgba(234, 179, 8, 0.5);
                border-radius: 8px;
                padding: 15px;
                color: #fbbf24;
                font-size: 12px;
            """)
            layout.addWidget(warning)
        
        # Logged-in user info
        user_section = QLabel(
            "<b>SENDER (Logged-In User):</b><br>"
            f"  Name: {self.logged_in_user.full_name}<br>"
            f"  Username: {self.logged_in_user.username}<br>"
            f"  Role: {self.logged_in_user.role.upper()}<br>"
            f"  Station: {self.logged_in_user.station_id or 'Not specified'}<br>"
            f"  Organization: {self.logged_in_user.organization or 'Not specified'}"
        )
        user_section.setWordWrap(True)
        user_section.setStyleSheet("background: rgba(15, 23, 42, 0.6); padding: 15px; border-radius: 8px; font-size: 13px; color: #e2e8f0;")
        layout.addWidget(user_section)
        
        # Certificate info (if available)
        if validation_result.get("identity"):
            identity = validation_result["identity"]
            
            cert_lines = [
                "<b>CERTIFICATE (Verified Identity):</b>",
                f"  Operator: {identity.get('operator_name', 'Unknown')}",
                f"  Organization: {identity.get('organization', 'Unknown')}",
                f"  Station: {identity.get('station_id', 'Unknown')}",
                f"  Department: {identity.get('department', 'Not specified')}",
                f"  Email: {identity.get('email', 'Not specified')}",
            ]

            if validation_result.get("serial"):
                cert_lines.append(f"  Certificate Serial: {validation_result['serial']}")
            if identity.get('fingerprint'):
                cert_lines.append(f"  Key Fingerprint: {identity['fingerprint']}")

            cert_lines.append("<br><b>Certificate Authority (Signed By):</b>")
            cert_lines.append(f"  CA Name: {validation_result['signed_by']}")
            if validation_result.get('issuer_fingerprint'):
                cert_lines.append(f"  CA Fingerprint: {validation_result['issuer_fingerprint']}")
            cert_lines.append(f"  Status: {validation_result['certificate_status']}")
            if validation_result.get('valid_from'):
                cert_lines.append(f"  Valid From: {validation_result['valid_from']}")
            cert_lines.append(f"  Expires: {validation_result['expires']}")

            cert_section = QLabel("<br>".join(cert_lines))
            cert_section.setWordWrap(True)
            cert_section.setStyleSheet("""
                background: rgba(34, 211, 238, 0.1);
                border: 2px solid rgba(34, 211, 238, 0.3);
                border-radius: 8px;
                padding: 15px;
                color: #e2e8f0;
                font-size: 13px;
            """)
            layout.addWidget(cert_section)
        
        # File info
        file_info = QLabel(
            f"<b>FILE TO TRANSFER:</b><br>"
            f"  Name: {self.selected_file.name}<br>"
            f"  Size: {self.selected_file.stat().st_size / (1024*1024):.2f} MB<br>"
            f"  Path: {self.selected_file.parent}"
        )
        file_info.setWordWrap(True)
        file_info.setStyleSheet("background: rgba(15, 23, 42, 0.6); padding: 15px; border-radius: 8px; font-size: 13px; color: #e2e8f0;")
        layout.addWidget(file_info)
        
        # Confirmation message
        confirm_msg = QLabel(
            "The receiver will see the above identity information.\n"
            "Do you confirm this information is correct and wish to proceed?"
        )
        confirm_msg.setWordWrap(True)
        confirm_msg.setStyleSheet("color: #94a3b8; font-size: 12px; margin-top: 10px;")
        layout.addWidget(confirm_msg)
        
        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Yes | QDialogButtonBox.StandardButton.No
        )
        button_box.button(QDialogButtonBox.StandardButton.Yes).setText("Confirm & Proceed")
        button_box.button(QDialogButtonBox.StandardButton.No).setText("Cancel Transfer")
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        button_box.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 10px 20px;
                min-height: 35px;
                min-width: 120px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
        """)
        layout.addWidget(button_box)
        
        # Apply dark theme
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
        """)
        
        return dialog.exec() == QDialog.DialogCode.Accepted
    
    def _load_certificate(self) -> Optional[dict]:
        """Load sender certificate if available."""
        try:
            from airseal_common.certificates import Certificate

            username = getattr(self.logged_in_user, "username", None)

            search_paths: list[Path] = []
            program_data_root = Path("C:/ProgramData/AirSeal/certificates")
            test_root = Path(__file__).parent.parent.parent / "test_certificates"

            if username:
                search_paths.append(program_data_root / f"{username}_certificate.json")
            search_paths.append(program_data_root / "sender_certificate.json")

            if username:
                search_paths.append(test_root / username / f"{username}_certificate.json")
            search_paths.append(test_root / "sender_certificate.json")

            checked: set[Path] = set()
            for path in search_paths:
                if path in checked:
                    continue
                checked.add(path)
                if not path.exists():
                    continue

                cert = Certificate.load(path)
                self.certificate_path = path

                if isinstance(cert.subject, dict):
                    operator_name = cert.subject.get('operator_name', 'Unknown')
                    station_id = cert.subject.get('station_id', 'Unknown')
                else:
                    operator_name = getattr(cert.subject, 'operator_name', 'Unknown')
                    station_id = getattr(cert.subject, 'station_id', 'Unknown')

                print(f"[OK] Loaded certificate: {operator_name} ({station_id}) [source: {path.name}]")

                if cert.public_key_fingerprint and cert.public_key_fingerprint != self.sender_fingerprint:
                    print("WARNING: Certificate public key does not match loaded sender key fingerprint. "
                          "Ensure the correct private key is available for this operator.")

                return cert.to_dict()

            self.certificate_path = None
            print("[INFO] No certificate found - manifest will use fingerprint only")
            return None

        except Exception as e:
            self.certificate_path = None
            print(f"WARNING: Could not load certificate: {e}")
            return None
    
    def _reset_session(self) -> None:
        self.selected_file = None
        self.manifest = None
        self.scan_worker = None

        self.drop_zone.setProperty("fileSelected", "false")
        self.drop_zone.setText("Drop a file or choose from disk")
        self.drop_zone.style().unpolish(self.drop_zone)
        self.drop_zone.style().polish(self.drop_zone)

        self.file_meta_label.setText("No file selected")
        self.log_view.clear()
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(False)
        self.delivery_card.setEnabled(False)
        self.summary_label.setText("Manifest summary will appear after analysis completes.")
        self.qr_label.setText("QR output pending")
        self.copy_hash_btn.setEnabled(False)
        self.save_manifest_btn.setEnabled(False)
        self.copy_manifest_btn.setEnabled(False)

    def _clear_log(self) -> None:
        self.log_view.clear()
        self.statusBar().showMessage("Log cleared", 2000)

    def _primary_button_style(self) -> str:
        return (
            "QPushButton {"
            " background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
            " stop:0 #22d3ee, stop:1 #0ea5e9);"
            " color: #0f172a;"
            " border-radius: 10px;"
            " padding: 10px 24px;"
            " font-weight: 600;"
            " letter-spacing: 0.3px;"
            "}"
            "QPushButton:hover {"
            " background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
            " stop:0 #0ea5e9, stop:1 #0284c7);"
            "}"
            "QPushButton:disabled {"
            " background: rgba(148, 163, 184, 0.20);"
            " color: rgba(148, 163, 184, 0.55);"
            "}"
        )

    def _secondary_button_style(self) -> str:
        return (
            "QPushButton {"
            " background: rgba(148, 163, 184, 0.08);"
            " color: #cbd5f5;"
            " border: 1px solid rgba(148, 163, 184, 0.25);"
            " border-radius: 10px;"
            " padding: 10px 24px;"
            " font-weight: 500;"
            "}"
            "QPushButton:hover {"
            " background: rgba(148, 163, 184, 0.15);"
            "}"
        )


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = SenderMainWindow()
    window.statusBar().showMessage("Ready")
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
