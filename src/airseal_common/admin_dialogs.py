"""
AirSeal Admin Dialogs

UI components for:
- User login
- User management
- Certificate generation for users
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QComboBox,
    QGroupBox,
    QFormLayout,
    QTextEdit,
    QStyle,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from airseal_common.user_management import UserDatabase, User, get_user_database
from airseal_common.certificates import CertificateAuthority, SenderIdentity
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class LoginDialog(QDialog):
    """User login dialog."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AirSeal Login")
        self.setModal(True)
        self.setMinimumWidth(400)
        
        self.user_db = get_user_database()
        self.authenticated_user: Optional[User] = None
        
        self._build_ui()
        self._apply_styles()
    
    def _build_ui(self):
        """Build login UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title = QLabel("AirSeal Login")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Enter your credentials to continue")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        layout.addWidget(subtitle)
        
        layout.addSpacing(10)
        
        # Username
        username_label = QLabel("Username:")
        username_label.setStyleSheet("font-weight: 600; color: #e2e8f0;")
        layout.addWidget(username_label)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        self.username_input.setMinimumHeight(40)
        self.username_input.returnPressed.connect(self._attempt_login)
        layout.addWidget(self.username_input)
        
        # Password
        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-weight: 600; color: #e2e8f0;")
        layout.addWidget(password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.returnPressed.connect(self._attempt_login)
        layout.addWidget(self.password_input)
        
        layout.addSpacing(10)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(45)
        self.login_btn.clicked.connect(self._attempt_login)
        button_layout.addWidget(self.login_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumHeight(45)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Focus on username
        self.username_input.setFocus()
    
    def _attempt_login(self):
        """Attempt to authenticate user."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Login Failed", "Please enter both username and password")
            return
        
        # Authenticate
        user = self.user_db.authenticate(username, password)
        
        if user:
            self.authenticated_user = user
            QMessageBox.information(
                self,
                "Login Successful",
                f"Welcome, {user.full_name}!\nRole: {user.role.capitalize()}"
            )
            self.accept()
        else:
            QMessageBox.critical(
                self,
                "Login Failed",
                "Invalid username or password.\nPlease try again."
            )
            self.password_input.clear()
            self.password_input.setFocus()
    
    def _apply_styles(self):
        """Apply stylesheet."""
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
            QLineEdit {
                background: rgba(15, 23, 42, 0.6);
                border: 2px solid rgba(148, 163, 184, 0.3);
                border-radius: 8px;
                padding: 8px 12px;
                color: #f8fafc;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #22d3ee;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 600;
                padding: 10px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0891b2, stop:1 #0369a1);
            }
        """)


class UserManagementDialog(QDialog):
    """User management dialog for admins."""
    
    def __init__(self, admin_user: User, parent=None):
        super().__init__(parent)
        self.setWindowTitle("User Management")
        self.setMinimumSize(900, 600)
        
        self.admin_user = admin_user
        self.user_db = get_user_database()
        
        if admin_user.role != "admin":
            QMessageBox.critical(self, "Access Denied", "Only administrators can manage users")
            self.reject()
            return
        
        self._build_ui()
        self._apply_styles()
        self._load_users()
    
    def _build_ui(self):
        """Build user management UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("👥 User Management")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # User table
        self.user_table = QTableWidget()
        self.user_table.setColumnCount(7)
        self.user_table.setHorizontalHeaderLabels([
            "Username", "Full Name", "Role", "Organization", "Station ID", "Status", "Last Login"
        ])
        self.user_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.user_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.user_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.user_table)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        add_btn = QPushButton("➕ Add User")
        add_btn.clicked.connect(self._add_user)
        button_layout.addWidget(add_btn)
        
        edit_btn = QPushButton("Edit User")
        edit_btn.clicked.connect(self._edit_user)
        button_layout.addWidget(edit_btn)
        
        reset_pwd_btn = QPushButton("🔑 Reset Password")
        reset_pwd_btn.clicked.connect(self._reset_password)
        button_layout.addWidget(reset_pwd_btn)
        
        toggle_btn = QPushButton("🔄 Toggle Status")
        toggle_btn.clicked.connect(self._toggle_status)
        button_layout.addWidget(toggle_btn)
        
        delete_btn = QPushButton("Delete User")
        delete_btn.clicked.connect(self._delete_user)
        button_layout.addWidget(delete_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
    
    def _load_users(self):
        """Load users into table."""
        self.user_table.setRowCount(0)
        users = self.user_db.list_users()
        
        for user in users:
            row = self.user_table.rowCount()
            self.user_table.insertRow(row)
            
            self.user_table.setItem(row, 0, QTableWidgetItem(user.username))
            self.user_table.setItem(row, 1, QTableWidgetItem(user.full_name))
            self.user_table.setItem(row, 2, QTableWidgetItem(user.role.capitalize()))
            self.user_table.setItem(row, 3, QTableWidgetItem(user.organization))
            self.user_table.setItem(row, 4, QTableWidgetItem(user.station_id or "N/A"))
            
            status = "Active" if user.is_active else "Inactive"
            self.user_table.setItem(row, 5, QTableWidgetItem(status))
            
            from datetime import datetime
            last_login = "Never"
            if user.last_login:
                last_login = datetime.fromtimestamp(user.last_login).strftime("%Y-%m-%d %H:%M")
            self.user_table.setItem(row, 6, QTableWidgetItem(last_login))
    
    def _add_user(self):
        """Add new user."""
        dialog = AddUserDialog(self.admin_user, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._load_users()
    
    def _edit_user(self):
        """Edit selected user."""
        selected = self.user_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No Selection", "Please select a user to edit")
            return
        
        username = self.user_table.item(selected, 0).text()
        # TODO: Implement edit dialog
        QMessageBox.information(self, "Not Implemented", "User editing coming soon!")
    
    def _reset_password(self):
        """Reset user password."""
        selected = self.user_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No Selection", "Please select a user")
            return
        
        username = self.user_table.item(selected, 0).text()
        
        new_password, ok = QLineEdit().text(), True
        # Simple input dialog
        from PySide6.QtWidgets import QInputDialog
        new_password, ok = QInputDialog.getText(
            self,
            "Reset Password",
            f"Enter new password for {username}:",
            QLineEdit.EchoMode.Password
        )
        
        if ok and new_password:
            try:
                self.user_db.reset_password(username, new_password, self.admin_user)
                QMessageBox.information(self, "Success", f"Password reset for {username}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reset password: {e}")
    
    def _toggle_status(self):
        """Toggle user active status."""
        selected = self.user_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No Selection", "Please select a user")
            return
        
        username = self.user_table.item(selected, 0).text()
        user = self.user_db.get_user(username)
        
        if user:
            if user.is_active:
                self.user_db.deactivate_user(username, self.admin_user)
            else:
                self.user_db.activate_user(username, self.admin_user)
            
            self._load_users()
    
    def _delete_user(self):
        """Delete selected user."""
        selected = self.user_table.currentRow()
        if selected < 0:
            QMessageBox.warning(self, "No Selection", "Please select a user to delete")
            return
        
        username = self.user_table.item(selected, 0).text()
        
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete user '{username}'?\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.user_db.delete_user(username, self.admin_user)
                self._load_users()
                QMessageBox.information(self, "Success", f"User '{username}' deleted")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete user: {e}")
    
    def _apply_styles(self):
        """Apply stylesheet."""
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
            QTableWidget {
                background: rgba(15, 23, 42, 0.6);
                border: 1px solid rgba(148, 163, 184, 0.3);
                border-radius: 8px;
                gridline-color: rgba(148, 163, 184, 0.2);
                color: #f8fafc;
            }
            QTableWidget::item:selected {
                background: rgba(34, 211, 238, 0.3);
            }
            QHeaderView::section {
                background: rgba(30, 41, 59, 0.8);
                color: #22d3ee;
                padding: 8px;
                border: none;
                font-weight: 600;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #22d3ee, stop:1 #0ea5e9);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
        """)


class AddUserDialog(QDialog):
    """Dialog for adding new users."""
    
    def __init__(self, admin_user: User, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New User")
        self.setMinimumWidth(500)
        
        self.admin_user = admin_user
        self.user_db = get_user_database()
        
        self._build_ui()
        self._apply_styles()
    
    def _build_ui(self):
        """Build add user UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("Add New User")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Form
        form = QFormLayout()
        form.setSpacing(10)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("e.g., sjohnson")
        form.addRow("Username*:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Min 12 chars: uppercase, lowercase, digit, special")
        form.addRow("Password*:", self.password_input)
        
        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("e.g., Dr. Sarah Johnson")
        form.addRow("Full Name*:", self.full_name_input)
        
        self.role_combo = QComboBox()
        self.role_combo.addItems(["operator", "admin", "viewer"])
        form.addRow("Role*:", self.role_combo)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("e.g., sjohnson@hospital.org")
        form.addRow("Email:", self.email_input)
        
        self.station_input = QLineEdit()
        self.station_input.setPlaceholderText("e.g., Medical-Scan-01")
        form.addRow("Station ID:", self.station_input)
        
        self.org_input = QLineEdit()
        self.org_input.setPlaceholderText("e.g., City Hospital")
        form.addRow("Organization:", self.org_input)
        
        self.dept_input = QLineEdit()
        self.dept_input.setPlaceholderText("e.g., IT Security")
        form.addRow("Department:", self.dept_input)
        
        layout.addLayout(form)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        create_btn = QPushButton("Create User")
        create_btn.clicked.connect(self._create_user)
        button_layout.addWidget(create_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
    
    def _create_user(self):
        """Create new user with password validation."""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        full_name = self.full_name_input.text().strip()
        role = self.role_combo.currentText()
        
        if not username or not password or not full_name:
            QMessageBox.warning(self, "Validation Error", "Please fill in all required fields (marked with *)")
            return
        
        try:
            # Password validation will be performed by create_user
            self.user_db.create_user(
                username=username,
                password=password,
                role=role,
                full_name=full_name,
                email=self.email_input.text().strip() or None,
                station_id=self.station_input.text().strip() or None,
                organization=self.org_input.text().strip() or "",
                department=self.dept_input.text().strip() or ""
            )
            
            QMessageBox.information(self, "Success", f"User '{username}' created successfully!")
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to create user: {e}")
    
    def _apply_styles(self):
        """Apply stylesheet."""
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
            QLineEdit, QComboBox {
                background: rgba(15, 23, 42, 0.6);
                border: 2px solid rgba(148, 163, 184, 0.3);
                border-radius: 6px;
                padding: 6px 10px;
                color: #f8fafc;
                font-size: 13px;
                min-height: 30px;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #22d3ee;
            }
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
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
            QLabel {
                color: #e2e8f0;
            }
        """)


class CertificateGenerationDialog(QDialog):
    """Dialog for generating operator certificates."""
    
    def __init__(self, admin_user: User, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Operator Certificate")
        self.setMinimumWidth(600)
        
        self.admin_user = admin_user
        self.user_db = get_user_database()
        self.generated_cert = None
        
        self._build_ui()
        self._apply_styles()
    
    def _build_ui(self):
        """Build certificate generation UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title and description
        title = QLabel("Generate Operator Certificate")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        desc = QLabel(
            "Create a certificate that binds the operator's identity to their cryptographic key.\n"
            "This certificate will be verified by receivers to prove the sender's identity."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #94a3b8; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(desc)
        
        # User selection
        user_group = QGroupBox("Select User")
        user_layout = QVBoxLayout(user_group)
        
        self.user_combo = QComboBox()
        self._load_users()
        self.user_combo.currentIndexChanged.connect(self._on_user_selected)
        user_layout.addWidget(self.user_combo)
        
        layout.addWidget(user_group)
        
        # Certificate details
        cert_group = QGroupBox("Certificate Details")
        form = QFormLayout(cert_group)
        form.setSpacing(10)
        
        self.operator_name_input = QLineEdit()
        self.operator_name_input.setPlaceholderText("Full name of the operator")
        form.addRow("Operator Name*:", self.operator_name_input)
        
        self.org_input = QLineEdit()
        self.org_input.setPlaceholderText("e.g., City Hospital")
        form.addRow("Organization*:", self.org_input)
        
        self.station_input = QLineEdit()
        self.station_input.setPlaceholderText("e.g., Medical-Scan-01")
        form.addRow("Station ID*:", self.station_input)
        
        self.dept_input = QLineEdit()
        self.dept_input.setPlaceholderText("e.g., Radiology Department")
        form.addRow("Department:", self.dept_input)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("e.g., operator@hospital.org")
        form.addRow("Email:", self.email_input)
        
        self.validity_input = QLineEdit()
        self.validity_input.setText("365")
        self.validity_input.setPlaceholderText("Days until expiration")
        form.addRow("Validity (days)*:", self.validity_input)
        
        layout.addWidget(cert_group)
        
        # Info box
        info_box = QLabel(
            "[INFO] The certificate will be signed by the Certificate Authority (CA).\n"
            "Receivers must have the CA certificate to verify this certificate."
        )
        info_box.setWordWrap(True)
        info_box.setStyleSheet("""
            background: rgba(34, 211, 238, 0.1);
            border: 1px solid rgba(34, 211, 238, 0.3);
            border-radius: 6px;
            padding: 10px;
            color: #22d3ee;
            font-size: 11px;
        """)
        layout.addWidget(info_box)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        generate_btn = QPushButton("Generate Certificate")
        generate_btn.clicked.connect(self._generate_certificate)
        button_layout.addWidget(generate_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background: rgba(148, 163, 184, 0.2);
                color: #cbd5e1;
            }
            QPushButton:hover {
                background: rgba(148, 163, 184, 0.3);
            }
        """)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        # Load first user's data
        if self.user_combo.count() > 0:
            self._on_user_selected(0)
    
    def _load_users(self):
        """Load available users into combo box."""
        self.user_combo.clear()
        for username, user in self.user_db.users.items():
            display_text = f"{user.full_name} ({username}) - {user.role.upper()}"
            self.user_combo.addItem(display_text, username)
    
    def _on_user_selected(self, index):
        """Populate form with user data when selected."""
        if index < 0:
            return
        
        username = self.user_combo.itemData(index)
        user = self.user_db.get_user(username)
        
        if user:
            self.operator_name_input.setText(user.full_name)
            self.org_input.setText(user.organization or "")
            self.station_input.setText(user.station_id or "")
            self.dept_input.setText(user.department or "")
            self.email_input.setText(user.email or "")
    
    def _generate_certificate(self):
        """Generate the certificate."""
        # Validate inputs
        operator_name = self.operator_name_input.text().strip()
        organization = self.org_input.text().strip()
        station_id = self.station_input.text().strip()
        validity_days_str = self.validity_input.text().strip()
        
        if not operator_name or not organization or not station_id:
            QMessageBox.warning(
                self,
                "Validation Error",
                "Please fill in all required fields (marked with *)"
            )
            return
        
        try:
            validity_days = int(validity_days_str)
            if validity_days <= 0:
                raise ValueError("Validity must be positive")
        except ValueError:
            QMessageBox.warning(
                self,
                "Validation Error",
                "Validity days must be a positive number"
            )
            return
        
        username = self.user_combo.currentData()
        
        try:
            # Load or create CA
            from pathlib import Path
            ca_path = Path("test_certificates")
            ca_cert_path = ca_path / "ca_certificate.json"
            ca_key_path = ca_path / "ca_private_key.pem"
            
            if not ca_cert_path.exists() or not ca_key_path.exists():
                reply = QMessageBox.question(
                    self,
                    "CA Not Found",
                    "Certificate Authority (CA) not found. Would you like to create one?\n\n"
                    "The CA is needed to sign operator certificates.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    self._create_ca(ca_path)
                else:
                    return
            
            # Load CA
            from cryptography.hazmat.primitives import serialization
            
            with open(ca_key_path, 'rb') as f:
                ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

            with open(ca_cert_path, 'r', encoding='utf-8') as f:
                import json
                ca_metadata = json.load(f)

            ca_public_key = serialization.load_pem_public_key(ca_metadata["public_key_pem"].encode('utf-8'))
            ca = CertificateAuthority(ca_metadata["name"], ca_private_key, ca_public_key)

            if ca_metadata.get("fingerprint") and ca_metadata["fingerprint"] != ca.fingerprint:
                raise ValueError(
                    "CA private key does not match the published CA certificate fingerprint "
                    f"(expected {ca_metadata['fingerprint']}, got {ca.fingerprint})."
                )
            
            # Create sender identity
            identity = SenderIdentity(
                operator_name=operator_name,
                organization=organization,
                station_id=station_id,
                department=self.dept_input.text().strip() or None,
                email=self.email_input.text().strip() or None
            )
            
            # Generate key pair for operator
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            operator_private_key = Ed25519PrivateKey.generate()
            operator_public_key = operator_private_key.public_key()
            
            # Issue certificate
            cert = ca.issue_certificate(identity, operator_public_key, validity_days)
            
            # Save certificate and private key
            cert_dir = Path(f"test_certificates/{username}")
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Save certificate
            cert_path = cert_dir / f"{username}_certificate.json"
            with open(cert_path, 'w') as f:
                json.dump(cert.to_dict(), f, indent=2)
            
            # Save private key
            key_path = cert_dir / f"{username}_private_key.pem"
            pem = operator_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_path, 'wb') as f:
                f.write(pem)
            
            # Show success
            QMessageBox.information(
                self,
                "Success",
                f"Certificate generated successfully!\n\n"
                f"Certificate saved to:\n{cert_path}\n\n"
                f"Private key saved to:\n{key_path}\n\n"
                f"Valid for {validity_days} days\n"
                f"Issued by: {ca_metadata['name']}"
            )
            
            self.generated_cert = cert
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to generate certificate:\n{str(e)}"
            )
    
    def _create_ca(self, ca_path: Path):
        """Create a new Certificate Authority."""
        ca_path.mkdir(parents=True, exist_ok=True)
        
        # Generate CA key pair
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        ca_private_key = Ed25519PrivateKey.generate()
        ca_public_key = ca_private_key.public_key()

        # Name the CA using organization context for clarity
        base_name = self.admin_user.organization or "AirSeal System"
        ca_name = base_name if "CA" in base_name.upper() else f"{base_name} Root CA"

        ca = CertificateAuthority(ca_name, ca_private_key, ca_public_key)
        ca_metadata = ca.export_ca_certificate()

        # Save CA certificate
        import json
        cert_path = ca_path / "ca_certificate.json"
        with open(cert_path, 'w', encoding='utf-8') as f:
            json.dump(ca_metadata, f, indent=2)
        
        # Save CA private key
        from cryptography.hazmat.primitives import serialization
        key_path = ca_path / "ca_private_key.pem"
        pem = ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, 'wb') as f:
            f.write(pem)
        
        QMessageBox.information(
            self,
            "CA Created",
            f"Certificate Authority created successfully!\n\n"
            f"Name: {ca_metadata['name']}\n"
            f"Fingerprint: {ca_metadata['fingerprint']}\n\n"
            f"CA Certificate: {cert_path}\n"
            f"CA Private Key: {key_path}\n\n"
            f"Distribute the certificate to receivers and store the private key securely."
        )
    
    def _apply_styles(self):
        """Apply stylesheet."""
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1e293b, stop:1 #0f172a);
                color: #e2e8f0;
            }
            QGroupBox {
                border: 2px solid rgba(148, 163, 184, 0.3);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: 600;
                color: #22d3ee;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit, QComboBox {
                background: rgba(15, 23, 42, 0.6);
                border: 2px solid rgba(148, 163, 184, 0.3);
                border-radius: 6px;
                padding: 6px 10px;
                color: #f8fafc;
                font-size: 13px;
                min-height: 30px;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #22d3ee;
            }
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
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #06b6d4, stop:1 #0284c7);
            }
            QLabel {
                color: #e2e8f0;
            }
        """)
