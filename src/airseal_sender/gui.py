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

    def __init__(self, source: Path, sender_key: KeyPair, nonce: str, transfer_id: str) -> None:
        super().__init__()
        self._source = source
        self._sender_key = sender_key
        self._nonce = nonce
        self._transfer_id = transfer_id

    def run(self) -> None:
        """Execute real analysis pipeline with backend."""
        try:
            # Step 1: Hash file
            self.progress.emit("Computing SHA-256 hash...")
            self.progress_value.emit(20)
            file_hash = compute_file_hash(self._source)
            self.progress.emit(f"✓ Hash: {file_hash[:16]}...")
            
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
            self.progress.emit(f"✓ Scan: {scan_result.status} ({scan_result.engine})")
            
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
            )
            self.progress.emit("✓ Manifest created")
            
            # Step 4: Sign manifest
            self.progress.emit("Signing with Ed25519...")
            self.progress_value.emit(80)
            signer = ManifestSigner(self._sender_key)
            signed_manifest = signer.sign_manifest(manifest)
            self.progress.emit(f"✓ Signature: {signed_manifest.signature[:16]}...")
            
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
            
            self.progress.emit("✓ QR code generated")
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

        self.selected_file: Optional[Path] = None
        self.manifest: Optional[dict] = None
        self.scan_worker: Optional[ScanWorker] = None
        self.qr_pixmap: Optional[QPixmap] = None
        
        # Initialize sender key using shared key storage for testing
        from shared_keys import get_or_create_sender_key
        self.sender_key = get_or_create_sender_key()
        self.sender_fingerprint = self.sender_key.get_fingerprint()
        
        # Nonce data (to be scanned from receiver)
        self.nonce: Optional[str] = None
        self.transfer_id: Optional[str] = None

        self._build_ui()

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
        
        # Generate nonce for this transfer
        if not self.nonce:
            import secrets
            self.nonce = secrets.token_hex(32)
            self.transfer_id = secrets.token_hex(16)

        self.scan_btn.setEnabled(False)
        self.log_view.clear()
        self.progress_bar.setValue(0)

        worker = ScanWorker(self.selected_file, self.sender_key, self.nonce, self.transfer_id)
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
            self.log_view.append("✓ Analysis pipeline completed successfully.")
            
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
