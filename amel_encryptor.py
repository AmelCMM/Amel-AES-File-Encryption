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


SALT_LEN       = 16
NONCE_LEN      = 12
HEADER_LEN     = SALT_LEN + NONCE_LEN
FORMAT_VERSION = b'\x02'


class CryptoWorker(QThread):
    progress = pyqtSignal(int)
    success  = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, mode: str, file_path: str, password: str):
        super().__init__()
        self.mode      = mode
        self.file_path = file_path
        self.password  = password

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

    def run(self):
        try:
            if self.mode == "encrypt":
                self._encrypt()
            else:
                self._decrypt()
        except Exception as exc:
            self.error.emit(str(exc))

    def _encrypt(self):
        self.progress.emit(10)
        with open(self.file_path, "rb") as f:
            data = f.read()

        self.progress.emit(25)
        original_name     = os.path.basename(self.file_path).encode()
        original_name_len = len(original_name).to_bytes(2, "big")
        plaintext         = original_name_len + original_name + data

        self.progress.emit(40)
        salt  = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key   = self._derive_key(self.password, salt)

        self.progress.emit(60)
        aesgcm     = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        self.progress.emit(85)
        output_path = self._safe_path(self.file_path + ".amel")
        with open(output_path, "wb") as f:
            f.write(FORMAT_VERSION + salt + nonce + ciphertext)

        self.progress.emit(100)
        self.success.emit(f"Encrypted -> {output_path}")

    def _decrypt(self):
        self.progress.emit(10)
        with open(self.file_path, "rb") as f:
            content = f.read()

        self.progress.emit(25)
        version = content[0:1]
        if version != FORMAT_VERSION:
            self.error.emit(
                f"Unsupported file version: {version!r}. "
                "This file may have been encrypted with an older version of the tool."
            )
            return

        salt       = content[1 : 1 + SALT_LEN]
        nonce      = content[1 + SALT_LEN : 1 + SALT_LEN + NONCE_LEN]
        ciphertext = content[1 + SALT_LEN + NONCE_LEN :]

        key    = self._derive_key(self.password, salt)
        aesgcm = AESGCM(key)

        self.progress.emit(55)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            self.error.emit("Decryption failed — wrong password or corrupted file.")
            return

        self.progress.emit(75)
        name_len      = int.from_bytes(plaintext[:2], "big")
        original_name = plaintext[2 : 2 + name_len].decode()
        file_data     = plaintext[2 + name_len :]

        output_path = self._safe_path(
            os.path.join(os.path.dirname(self.file_path), original_name)
        )
        with open(output_path, "wb") as f:
            f.write(file_data)

        self.progress.emit(100)
        self.success.emit(f"Decrypted → {output_path}")


class AmelEncryptor(QWidget):
    MIN_PASSWORD_LEN = 8

    def __init__(self):
        super().__init__()
        self.file_path: str | None         = None
        self.worker:    CryptoWorker | None = None

        self.setAcceptDrops(True)
        self.setWindowTitle("Amel AES File Encryptor V2")
        self.resize(500, 580)

        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(18, 18, 18))
        self.setPalette(palette)

        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'Segoe UI';
            }
            QLabel#header {
                font-size: 20px;
                font-weight: bold;
                color: #ffffff;
            }
            QLabel#badge {
                font-size: 11px;
                font-weight: normal;
                color: #4caf50;
                background-color: #1a2e1a;
                border: 1px solid #4caf50;
                border-radius: 4px;
                padding: 2px 8px;
            }
            QLabel { font-size: 13px; }
            QPushButton {
                background-color: #1565c0;
                border: none;
                color: white;
                padding: 10px;
                border-radius: 6px;
                font-size: 14px;
            }
            QPushButton:hover    { background-color: #0d47a1; }
            QPushButton:disabled { background-color: #2a2a2a; color: #555555; }
            QPushButton#decrypt_btn {
                background-color: #2a2a2a;
                border: 1px solid #444;
            }
            QPushButton#decrypt_btn:hover { background-color: #333333; }
            QLineEdit {
                background-color: #1e1e1e;
                border: 1px solid #333;
                border-radius: 4px;
                padding: 8px;
                color: #e0e0e0;
                font-size: 13px;
            }
            QLineEdit:focus { border: 1px solid #1565c0; }
            QCheckBox { font-size: 12px; color: #888888; }
            QProgressBar {
                background-color: #1e1e1e;
                border: 1px solid #333;
                border-radius: 4px;
                text-align: center;
                color: #888;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background-color: #1565c0;
                border-radius: 3px;
            }
        """)

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(24, 24, 24, 24)

        header = QLabel("Amel AES Encryptor")
        header.setObjectName("header")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        badge = QLabel("Zero Metadata Leakage")
        badge.setObjectName("badge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(badge)

        layout.addSpacing(6)

        self.file_label = QLabel("Drop a file here or use the button below")
        self.file_label.setWordWrap(True)
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setStyleSheet(
            "font-size: 12px; color: #555555; "
            "border: 1px dashed #333; border-radius: 6px; padding: 16px;"
        )
        layout.addWidget(self.file_label)

        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self._select_file)
        layout.addWidget(self.select_button)

        layout.addSpacing(4)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText(f"Password (min {self.MIN_PASSWORD_LEN} characters)")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Confirm password (encryption only)")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        self.toggle_visibility = QCheckBox("Show password")
        self.toggle_visibility.stateChanged.connect(self._toggle_password_visibility)
        layout.addWidget(self.toggle_visibility)

        layout.addSpacing(4)

        self.encrypt_button = QPushButton("Encrypt File  ->  .amel")
        self.encrypt_button.clicked.connect(self._encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File  <- .amel")
        self.decrypt_button.setObjectName("decrypt_btn")
        self.decrypt_button.clicked.connect(self._decrypt_file)
        layout.addWidget(self.decrypt_button)

        layout.addSpacing(4)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 11px; color: #555555;")
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.setLayout(layout)

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

    def _select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_path = path
            self.file_label.setText(path)
            self.file_label.setStyleSheet(
                "font-size: 12px; color: #90caf9; "
                "border: 1px dashed #1565c0; border-radius: 6px; padding: 16px;"
            )

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
                self.file_label.setStyleSheet(
                    "font-size: 12px; color: #90caf9; "
                    "border: 1px dashed #1565c0; border-radius: 6px; padding: 16px;"
                )

    def _on_progress(self, value: int):
        self.progress.setValue(value)

    def _on_success(self, message: str):
        self._set_controls_enabled(True)
        self.status_label.setText("")
        self.progress.setValue(0)
        QMessageBox.information(self, "Success", message)

    def _on_error(self, message: str):
        self.progress.setValue(0)
        self._set_controls_enabled(True)
        self.status_label.setText("")
        QMessageBox.critical(self, "Error", message)

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
