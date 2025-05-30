import os
import sys
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLabel,
    QLineEdit, QMessageBox, QProgressBar, QFileDialog, QCheckBox, QHBoxLayout
)
from PyQt6.QtCore import Qt, QMimeData
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QFont, QColor, QPalette
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class AmelEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setWindowTitle("Amel AES File Encryptor")
        self.resize(500, 520)

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
            QPushButton:hover {
                background-color: #005fa3;
            }
            QLineEdit {
                background-color: #2d2d2d;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                color: white;
            }
            QCheckBox {
                font-size: 13px;
            }
            QProgressBar {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #555;
                border-radius: 4px;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                width: 10px;
            }
        """)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        header = QLabel("\ud83d\udee1 Amel AES File Encryptor")
        header.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        self.file_label = QLabel("Drop a file here or use the button below")
        self.file_label.setWordWrap(True)
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.file_label)

        self.select_button = QPushButton("Select File")
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        self.confirm_input = QLineEdit()
        self.confirm_input.setPlaceholderText("Re-enter password")
        self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_input)

        self.toggle_visibility = QCheckBox("Show password")
        self.toggle_visibility.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.toggle_visibility)

        self.encrypt_button = QPushButton("Encrypt File (.amel)")
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File (.amel)")
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.setLayout(layout)

    def toggle_password_visibility(self):
        if self.toggle_visibility.isChecked():
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.file_label.setText(path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path):
                self.file_label.setText(file_path)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()
        confirm = self.confirm_input.text()

        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file.")
            return
        if not password or not confirm:
            QMessageBox.warning(self, "Error", "Please enter and confirm your password.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        try:
            self.progress.setValue(10)
            with open(file_path, "rb") as f:
                data = f.read()

            self.progress.setValue(30)
            salt = os.urandom(16)
            key = self.derive_key(password, salt)

            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            encrypted = aesgcm.encrypt(nonce, data, None)

            original_name = os.path.basename(file_path).encode()
            original_len = len(original_name).to_bytes(2, "big")
            output_path = file_path + ".amel"

            with open(output_path, "wb") as f:
                f.write(salt + nonce + original_len + original_name + encrypted)

            self.progress.setValue(100)
            QMessageBox.information(self, "Success", f"Encrypted file saved as:\n{output_path}")

        except Exception as e:
            QMessageBox.critical(self, "Encryption Error", str(e))

    def decrypt_file(self):
        file_path = self.file_label.text()
        password = self.password_input.text()

        if not file_path.endswith(".amel") or not os.path.isfile(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid .amel file.")
            return
        if not password:
            QMessageBox.warning(self, "Error", "Password is required for decryption.")
            return

        try:
            self.progress.setValue(10)
            with open(file_path, "rb") as f:
                content = f.read()

            salt = content[:16]
            nonce = content[16:28]
            name_len = int.from_bytes(content[28:30], "big")
            original_name = content[30:30+name_len].decode()
            ciphertext = content[30+name_len:]

            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)

            self.progress.setValue(60)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)

            output_path = os.path.join(os.path.dirname(file_path), original_name)
            with open(output_path, "wb") as f:
                f.write(decrypted)

            self.progress.setValue(100)
            QMessageBox.information(self, "Decryption Success", f"Decrypted file saved as:\n{output_path}")

        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", str(e))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = AmelEncryptor()
    window.show()
    sys.exit(app.exec())
