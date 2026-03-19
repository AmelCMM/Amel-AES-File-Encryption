import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QLineEdit, QMessageBox, QProgressBar, QFileDialog, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont, QColor, QPalette
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoWorker(QThread):
    progress = pyqtSignal(int)
    success  = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, mode: str, file_path: str, password: str):
        super().__init__()
        self.mode      = mode        # 'encrypt' | 'decrypt'
        self.file_path = file_path
        self.password  = password

    # ── Key derivation ──────────────────────────────────────────────────────
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        return kdf.derive(password.encode())

   
    @staticmethod
    def _safe_path(path: str) -> str:
        
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        counter = 1
        while os.path.exists(f"{base}_{counter}{ext}"):
            counter += 1
        return f"{base}_{counter}{ext}"

    # Thread entry point 
    def run(self):
        try:
            if self.mode == "encrypt":
                self._encrypt()
            else:
                self._decrypt()
        except Exception as exc:
            self.error.emit(str(exc))

    # Encrypt 
    def _encrypt(self):
        self.progress.emit(10)
        with open(self.file_path, "rb") as f:
            data = f.read()

        self.progress.emit(30)
        salt = os.urandom(16)
        key  = self._derive_key(self.password, salt)

        self.progress.emit(50)
        aesgcm    = AESGCM(key)
        nonce     = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, data, None)

        self.progress.emit(80)
        original_name = os.path.basename(self.file_path).encode()
        original_len  = len(original_name).to_bytes(2, "big")

        output_path = self._safe_path(self.file_path + ".amel")
        with open(output_path, "wb") as f:
            f.write(salt + nonce + original_len + original_name + encrypted)

        self.progress.emit(100)
        self.success.emit(f"Encrypted file saved as:\n{output_path}")

    # Decrypt
    def _decrypt(self):
        self.progress.emit(10)
        with open(self.file_path, "rb") as f:
            content = f.read()

        self.progress.emit(30)
        salt         = content[:16]
        nonce        = content[16:28]
        name_len     = int.from_bytes(content[28:30], "big")
        original_name = content[30:30 + name_len].decode()
        ciphertext   = content[30 + name_len:]

        key    = self._derive_key(self.password, salt)
        aesgcm = AESGCM(key)

        self.progress.emit(60)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)   # raises on bad password

        self.progress.emit(80)
        output_path = self._safe_path(
            os.path.join(os.path.dirname(self.file_path), original_name)
        )
        with open(output_path, "wb") as f:
            f.write(decrypted)

        self.progress.emit(100)
        self.success.emit(f"Decrypted file saved as:\n{output_path}")

#  Main window
class AmelEncryptor(QWidget):
    MIN_PASSWORD_LEN = 8

    def __init__(self):
        super().__init__()
        
        self.file_path: str | None = None
        self.worker:    CryptoWorker | None = None

        self.setAcceptDrops(True)
        self.setWindowTitle("Amel AES File Encryptor")
        self.resize(500, 560)

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        self.setPalette(palette)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: 'Segoe UI';
            }
            QLabel {
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton {
                background-color: #0078d4;
                border: none;
                color: white;
                padding: 10px;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover    { background-color: #005fa3; }
            QPushButton:disabled { background-color: #444444; color: #888888; }
            QLineEdit {
                background-color: #2d2d2d;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                color: white;
            }
            QCheckBox { font-size: 13px; }
            QProgressBar {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                width: 10px;
            }
        """)

        self._setup_ui()

    # Build UI 
    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)

        header = QLabel("🛡 Amel AES File Encryptor")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        self.file_label = QLabel("Drop a file here or use the button below")
        self.file_label.setWordWrap(True)
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setStyleSheet("font-size: 13px; font-weight: normal; color: #aaaaaa;")
        layout.addWidget(self.file_label)

        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self._select_file)
        layout.addWidget(self.select_button)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(f"Enter password (min {self.MIN_PASSWORD_LEN} characters)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Re-enter password (encryption only)")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        self.toggle_visibility = QCheckBox("Show password")
        self.toggle_visibility.stateChanged.connect(self._toggle_password_visibility)
        layout.addWidget(self.toggle_visibility)

        self.encrypt_button = QPushButton("Encrypt File (.amel)")
        self.encrypt_button.clicked.connect(self._encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File (.amel)")
        self.decrypt_button.clicked.connect(self._decrypt_file)
        layout.addWidget(self.decrypt_button)

        # Status text above progress bar
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 12px; font-weight: normal; color: #aaaaaa;")
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.setLayout(layout)

    #  UI helpers
    def _toggle_password_visibility(self):
        mode = (QLineEdit.EchoMode.Normal
                if self.toggle_visibility.isChecked()
                else QLineEdit.EchoMode.Password)
        self.password_input.setEchoMode(mode)
        self.confirm_input.setEchoMode(mode)

    def _set_controls_enabled(self, enabled: bool):
        self.encrypt_button.setEnabled(enabled)
        self.decrypt_button.setEnabled(enabled)
        self.select_button.setEnabled(enabled)

    # File selection
    def _select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_path = path
            self.file_label.setText(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.file_path = path
                self.file_label.setText(path)

    # Worker signal handlers
    def _on_progress(self, value: int):
        self.progress.setValue(value)

    def _on_success(self, message: str):
        self._set_controls_enabled(True)
        self.status_label.setText("")
        QMessageBox.information(self, "Success", message)

    def _on_error(self, message: str):
        self.progress.setValue(0)
        self._set_controls_enabled(True)
        self.status_label.setText("")
        QMessageBox.critical(self, "Error", message)

    # Encrypt
    def _encrypt_file(self):
        password = self.password_input.text()
        confirm  = self.confirm_input.text()

        if not self.file_path or not os.path.isfile(self.file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file.")
            return
    
        if len(password) < self.MIN_PASSWORD_LEN:
            QMessageBox.warning(
                self, "Weak Password",
                f"Password must be at least {self.MIN_PASSWORD_LEN} characters."
            )
            return
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
       
        self.progress.setValue(0)
        self._set_controls_enabled(False)
        self.status_label.setText("Encrypting…")

        self.worker = CryptoWorker("encrypt", self.file_path, password)
        self.worker.progress.connect(self._on_progress)
        self.worker.success.connect(self._on_success)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    # Decrypt
    def _decrypt_file(self):
        password = self.password_input.text()

        if (not self.file_path
                or not self.file_path.endswith(".amel")
                or not os.path.isfile(self.file_path)):
            QMessageBox.warning(self, "Error", "Please select a valid .amel file.")
            return
        if not password:
            QMessageBox.warning(self, "Error", "Password is required for decryption.")
            return

        self.progress.setValue(0)
        self._set_controls_enabled(False)
        self.status_label.setText("Decrypting…")

        self.worker = CryptoWorker("decrypt", self.file_path, password)
        self.worker.progress.connect(self._on_progress)
        self.worker.success.connect(self._on_success)
        self.worker.error.connect(self._on_error)
        self.worker.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AmelEncryptor()
    window.show()
    sys.exit(app.exec())
