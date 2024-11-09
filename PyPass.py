import sys
import secrets
import string
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit,
    QSpinBox, QCheckBox, QMessageBox, QInputDialog, QDialog, QScrollArea, QHBoxLayout
)
from PyQt5.QtCore import QTimer

class SecurePasswordGenerator(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.password_history = []  
        self.timer = QTimer()
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.clear_clipboard)
        self.master_key = None
        self.vault_path = "password_vault.enc"  

    def initUI(self):
        self.setWindowTitle('PyPass | Secure Password Generator')
        self.setFixedSize(400, 400)

        layout = QVBoxLayout()

        # Vault Creation Button
        self.create_vault_button = QPushButton('Create Vault')
        self.create_vault_button.clicked.connect(self.create_vault)
        layout.addWidget(self.create_vault_button)

        # Open Vault Button
        self.open_vault_button = QPushButton('Open Vault')
        self.open_vault_button.clicked.connect(self.open_vault)
        layout.addWidget(self.open_vault_button)

        # Character length setting
        self.length_label = QLabel('Password Length:')
        layout.addWidget(self.length_label)
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(16, 256)
        self.length_spinbox.setValue(32)
        layout.addWidget(self.length_spinbox)

        # Character options
        self.include_uppercase = QCheckBox('Include Uppercase Letters')
        self.include_uppercase.setChecked(True)
        layout.addWidget(self.include_uppercase)

        self.include_lowercase = QCheckBox('Include Lowercase Letters')
        self.include_lowercase.setChecked(True)
        layout.addWidget(self.include_lowercase)

        self.include_numbers = QCheckBox('Include Numbers')
        self.include_numbers.setChecked(True)
        layout.addWidget(self.include_numbers)

        self.include_special = QCheckBox('Include Special Characters')
        self.include_special.setChecked(True)
        layout.addWidget(self.include_special)

        # Exclude similar characters option
        self.exclude_similar = QCheckBox('Exclude Similar Characters (1, l, 0, O)')
        self.exclude_similar.setChecked(False)
        layout.addWidget(self.exclude_similar)

        # Generated password display
        self.password_display = QLineEdit()
        self.password_display.setReadOnly(True)
        layout.addWidget(self.password_display)

        # Show/Hide password toggle
        self.show_password_checkbox = QCheckBox('Show Password')
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        layout.addWidget(self.show_password_checkbox)

        # Generate button
        self.generate_button = QPushButton('Generate Secure Password')
        self.generate_button.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_button)

        # Copy button
        self.copy_button = QPushButton('Copy to Clipboard')
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(self.copy_button)

        # Save button
        self.save_button = QPushButton('Save Password to Vault')
        self.save_button.clicked.connect(self.save_password)
        layout.addWidget(self.save_button)

        # Password strength indicator
        self.strength_label = QLabel('Password Strength: ')
        layout.addWidget(self.strength_label)

        self.setLayout(layout)

    def create_vault(self):
        if os.path.exists(self.vault_path):
            QMessageBox.information(self, 'Vault Exists', 'Vault already exists.')
            return

        master_password, ok = QInputDialog.getText(self, 'Set Master Key', 'Enter a master key:', QLineEdit.Password)
        if ok and master_password:
            self.master_key = self.derive_key(master_password)
            with open(self.vault_path, 'wb') as vault_file:
                encrypted_data = Fernet(self.master_key).encrypt(b"{}")  # Empty JSON 
                vault_file.write(encrypted_data)
            QMessageBox.information(self, 'Vault Created', 'Vault created successfully! Keep your master key safe.')
        else:
            QMessageBox.warning(self, 'Invalid Input', 'Master key not set.')

    def derive_key(self, master_password):
        salt = b'\x12\x34\x56\x78'  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def generate_password(self):
        if not self.master_key:
            QMessageBox.warning(self, 'Vault Locked', 'Please create or unlock the vault first.')
            return

        length = self.length_spinbox.value()
        character_pool = ''
        if self.include_uppercase.isChecked():
            character_pool += string.ascii_uppercase
        if self.include_lowercase.isChecked():
            character_pool += string.ascii_lowercase
        if self.include_numbers.isChecked():
            character_pool += string.digits
        if self.include_special.isChecked():
            character_pool += string.punctuation

        if self.exclude_similar.isChecked():
            character_pool = character_pool.replace('1', '').replace('l', '').replace('0', '').replace('O', '')

        if not character_pool:
            QMessageBox.warning(self, 'Error', 'Please select at least one character set.')
            return

        password = ''.join(secrets.choice(character_pool) for _ in range(length))
        self.password_display.setText(password)
        self.update_password_strength(password)

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_display.text())
        QMessageBox.information(self, 'Copied', 'Password copied to clipboard.')
        self.timer.start(30000)  # Clear clipboard after 30 seconds

    def clear_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.clear()
        QMessageBox.information(self, 'Clipboard Cleared', 'Clipboard has been cleared.')

    def save_password(self):
        if not self.master_key:
            QMessageBox.warning(self, 'Vault Locked', 'Please create or unlock the vault first.')
            return

        password = self.password_display.text()
        if not password:
            QMessageBox.warning(self, 'No Password', 'Please generate a password first.')
            return

        # Prompt for a nickname
        nickname, ok = QInputDialog.getText(self, 'Nickname', 'Enter a nickname for the password:')
        if not ok or not nickname:
            QMessageBox.warning(self, 'Invalid Input', 'Nickname not provided.')
            return

        try:
            with open(self.vault_path, 'rb') as vault_file:
                encrypted_data = vault_file.read()
            data = json.loads(Fernet(self.master_key).decrypt(encrypted_data).decode())
            data[nickname] = password  # Save password with nickname as key

            with open(self.vault_path, 'wb') as vault_file:
                encrypted_data = Fernet(self.master_key).encrypt(json.dumps(data).encode())
                vault_file.write(encrypted_data)

            QMessageBox.information(self, 'Saved', f'Password saved to vault with nickname "{nickname}".')
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error saving password: {str(e)}')

    def open_vault(self):
        if not os.path.exists(self.vault_path):
            QMessageBox.warning(self, 'Vault Not Found', 'Please create a vault first.')
            return

        master_password, ok = QInputDialog.getText(self, 'Unlock Vault', 'Enter the master key:', QLineEdit.Password)
        if not ok or not master_password:
            return

        try:
            self.master_key = self.derive_key(master_password)
            with open(self.vault_path, 'rb') as vault_file:
                encrypted_data = vault_file.read()
            data = json.loads(Fernet(self.master_key).decrypt(encrypted_data).decode())

            # Display the contents of the vault
            vault_dialog = QDialog(self)
            vault_dialog.setWindowTitle('Vault Contents')
            vault_layout = QVBoxLayout(vault_dialog)

            if data:
                scroll_area = QScrollArea()
                scroll_widget = QWidget()
                scroll_layout = QVBoxLayout(scroll_widget)

                for nickname, password in data.items():
                    entry_layout = QHBoxLayout()
                    label = QLabel(f"{nickname}: {password}")
                    label.setWordWrap(True)  # Allow wrapping if the password is long
                    copy_button = QPushButton('Copy')
                    copy_button.clicked.connect(lambda _, pwd=password: self.copy_to_clipboard_custom(pwd))
                    entry_layout.addWidget(label)
                    entry_layout.addWidget(copy_button)
                    scroll_layout.addLayout(entry_layout)

                scroll_widget.setLayout(scroll_layout)
                scroll_area.setWidget(scroll_widget)
                scroll_area.setWidgetResizable(True)
                vault_layout.addWidget(scroll_area)
            else:
                no_data_label = QLabel('The vault is empty.')
                vault_layout.addWidget(no_data_label)

            close_button = QPushButton('Close')
            close_button.clicked.connect(vault_dialog.close)
            vault_layout.addWidget(close_button)

            vault_dialog.exec_()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f'Error opening vault: {str(e)}')

    def copy_to_clipboard_custom(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, 'Copied', 'Password copied to clipboard.')

    def toggle_password_visibility(self):
        self.password_display.setEchoMode(QLineEdit.Normal if self.show_password_checkbox.isChecked() else QLineEdit.Password)

    def update_password_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        strength = 0
        if length >= 16: strength += 1
        if has_upper: strength += 1
        if has_lower: strength += 1
        if has_digit: strength += 1
        if has_special: strength += 1

        self.strength_label.setText(f'Password Strength: {"Weak" if strength <= 2 else "Moderate" if strength == 3 else "Strong"}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    generator = SecurePasswordGenerator()
    generator.show()
    sys.exit(app.exec_())
