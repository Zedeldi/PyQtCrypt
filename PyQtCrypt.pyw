#!/usr/bin/env python3

# PyQtCrypt.pyw
# Copyright (C) 2020  Zack Didcott

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import base64
import hashlib
import os
import random
import shutil
import string
import sys
import webbrowser
from zipfile import ZipFile

from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (
    QApplication,
    QSystemTrayIcon,
    QDialog,
    QMessageBox,
    QFileDialog,
    QMenu,
    QAction,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QSpinBox,
    QComboBox,
    QVBoxLayout,
    QHBoxLayout,
)

# In case bundled with PyInstaller
# See https://pyinstaller.readthedocs.io/en/stable/runtime-information.html
BUNDLE_DIR = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
FALLBACK_ICON = os.path.abspath(os.path.join(BUNDLE_DIR, "assets", "briefcase.svg"))


def gen_key():
    filename = "".join(random.choice(string.ascii_uppercase) for _ in range(8)) + ".key"
    key = Fernet.generate_key()
    with open(filename, "wb") as key_file:
        key_file.write(key)
    return key, filename


def shred_file(filepath, iterations):
    f_size = os.path.getsize(filepath)
    try:
        with open(filepath, "wb") as f:
            for i in range(iterations):
                f.seek(0)
                f.write(os.urandom(f_size))
        random_filename = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(8)
        )
        os.rename(filepath, os.path.join(os.path.dirname(filepath), random_filename))
        return random_filename
    except OSError:
        # Probably no write permission (follows symlinks)
        # or extremely small chance of file name conflict - ignore
        pass


def list_files(directory):
    files = []
    for (dirpath, subdirs, filenames) in os.walk(directory):
        for f in filenames:
            files.append([os.path.relpath(dirpath, start=directory), f])
        else:
            # Include empty directories
            files.append([os.path.relpath(dirpath, start=directory), ""])
    return files


# Qt functions #
def show_info_dialog(icon, title, text):
    msg_box = QMessageBox()
    msg_box.setIcon(icon)
    msg_box.setWindowTitle(title)
    msg_box.setText(text)
    msg_box.setStandardButtons(QMessageBox.Ok)
    msg_box.exec_()


def get_directory(title):
    file_dialog = QFileDialog()
    file_dialog.setFileMode(QFileDialog.Directory)
    file_dialog.setWindowTitle(title)
    if file_dialog.exec_():
        return file_dialog.selectedFiles()[0]


class SettingsDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.key = None
        self.cryptdir = None
        self.plaindir = None
        self.shred = False
        self.shred_iterations = 1
        self.drive_letter = None

        self.setWindowTitle("PyQtCrypt - Settings")
        self.setWindowIcon(QIcon.fromTheme("preferences-system", QIcon(FALLBACK_ICON)))
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.resize(600, 100)

        # Widgets #
        self.text_pass = QLineEdit(self)
        self.text_pass.setPlaceholderText("Password (leave blank to generate)")
        self.text_pass.setEchoMode(QLineEdit.Password)
        self.button_keyfile = QPushButton("Keyfile", self)
        self.button_cryptdir = QPushButton("Directory", self)
        self.button_plaindir = QPushButton("Mountpoint", self)
        self.checkbox_shred = QCheckBox("Shred", self)
        self.checkbox_shred.setChecked(self.shred)
        self.spinbox_shred_iterations = QSpinBox(self)
        self.spinbox_shred_iterations.setRange(1, 20)
        self.spinbox_shred_iterations.setPrefix("Level: ")
        if not self.shred:
            self.spinbox_shred_iterations.hide()
        self.button_submit = QPushButton("Submit", self)

        # Actions #
        self.text_pass.returnPressed.connect(self.read_password)
        self.button_keyfile.clicked.connect(self.read_keyfile)
        self.button_cryptdir.clicked.connect(self.read_cryptdir)
        self.button_plaindir.clicked.connect(self.read_plaindir)
        self.checkbox_shred.stateChanged.connect(self.read_shred)
        self.spinbox_shred_iterations.valueChanged.connect(self.read_shred_iterations)
        self.button_submit.clicked.connect(self.return_prefs)

        # Layout #
        self.main_layout = QVBoxLayout()
        self.opt_layout = QHBoxLayout()

        self.opt_layout.addWidget(self.button_keyfile)
        self.opt_layout.addWidget(self.button_cryptdir)
        self.opt_layout.addWidget(self.button_plaindir)
        self.opt_layout.addWidget(self.checkbox_shred)
        self.opt_layout.addWidget(self.spinbox_shred_iterations)

        self.main_layout.addWidget(self.text_pass)
        self.main_layout.addLayout(self.opt_layout)
        self.main_layout.addWidget(self.button_submit)

        self.setLayout(self.main_layout)

        # Windows only #
        if os.name == "nt":
            self.drive_letter_selector = QComboBox()
            self.drive_letter_selector.addItems(
                map(lambda l: l + ":", list(string.ascii_lowercase))
            )
            self.drive_letter_selector.setCurrentIndex(25)
            self.drive_letter_selector.currentIndexChanged.connect(
                self.set_drive_letter
            )
            self.opt_layout.addWidget(self.drive_letter_selector)
            self.set_drive_letter()

    def read_password(self):
        if self.text_pass.text() != "":
            self.key = base64.urlsafe_b64encode(
                hashlib.sha256(self.text_pass.text().encode()).digest()
            )
        self.return_prefs()

    def read_keyfile(self):
        keyfile = QFileDialog.getOpenFileName(self, "Open keyfile")[0]
        try:
            self.key = open(keyfile, "rb").read()
            self.text_pass.setEchoMode(QLineEdit.Normal)
            self.text_pass.setReadOnly(True)
            self.text_pass.setText(os.path.basename(keyfile))
        except OSError:
            self.key = None

    def read_cryptdir(self):
        self.cryptdir = get_directory("Select Encrypted Directory")

    def read_plaindir(self):
        self.plaindir = get_directory("Select Mountpoint")

    def read_shred(self):
        if self.checkbox_shred.isChecked():
            self.shred = True
            self.spinbox_shred_iterations.show()
        else:
            self.shred = False
            self.spinbox_shred_iterations.hide()

    def read_shred_iterations(self):
        self.shred_iterations = self.spinbox_shred_iterations.value()

    def set_drive_letter(self):
        self.drive_letter = self.drive_letter_selector.currentText()

    def return_prefs(self):
        if not self.key and self.text_pass.text() == "":
            self.key, filename = gen_key()
            show_info_dialog(
                QMessageBox.Information,
                "Keyfile Saved",
                f"Your keyfile has been saved at {filename}.",
            )
        self.accept()
        return {
            "key": self.key,
            "cryptdir": self.cryptdir,
            "plaindir": self.plaindir,
            "shred": self.shred,
            "shred_iterations": self.shred_iterations,
            "drive_letter": self.drive_letter,
        }

    @staticmethod
    def get_prefs():
        dialog = SettingsDialog()
        if dialog.exec_():
            return dialog.return_prefs()


class PyQtCrypt(QSystemTrayIcon):
    def __init__(self):
        super().__init__()

        # Default settings #
        self.ABOUT_URL = "https://github.com/Zedeldi/PyQtCrypt"
        self.KEY = None
        self.CRYPT_DIR = os.path.abspath(".PyQtCrypt_Data")
        self.PLAIN_DIR = os.path.abspath("PyQtCrypt_Data")
        self.SHRED = False
        self.SHRED_ITERATIONS = 1
        self.OPEN_GUI = True

        self.is_mounted = False

        self.set_prefs()
        if self.KEY is None:
            # No key received, cancelled
            sys.exit(1)

        self.initUI()
        self.mount()

    def initUI(self):
        self.setIcon(QIcon.fromTheme("folder", QIcon(FALLBACK_ICON)))
        self.setVisible(True)
        self.setContextMenu(self.build_menu())
        self.activated.connect(self.on_activated)

    def build_menu(self):
        menu = QMenu()
        self.toggle_mount_action = QAction("Unmount", self)
        self.toggle_mount_action.triggered.connect(self.toggle_mount)
        menu.addAction(self.toggle_mount_action)
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.set_prefs)
        menu.addAction(settings_action)
        about_action = QAction("About", self)
        about_action.triggered.connect(self.about)
        menu.addAction(about_action)
        menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit)
        menu.addAction(quit_action)
        return menu

    def on_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.toggle_mount()
        elif reason == QSystemTrayIcon.MiddleClick:
            self.set_prefs()

    def set_prefs(self):
        if prefs := SettingsDialog.get_prefs():
            if self.is_mounted:
                was_mounted = True
                self.unmount()
            else:
                was_mounted = False
            if prefs["key"]:
                try:
                    Fernet(prefs["key"])
                    self.KEY = prefs["key"]
                except ValueError:
                    show_info_dialog(
                        QMessageBox.Critical,
                        "Invalid key!",
                        "The provided password/keyfile is invalid.",
                    )
                    sys.exit(1)
            if prefs["cryptdir"]:
                self.CRYPT_DIR = prefs["cryptdir"]
            if prefs["plaindir"]:
                self.PLAIN_DIR = prefs["plaindir"]
            self.SHRED = prefs["shred"]  # True/False
            self.SHRED_ITERATIONS = prefs["shred_iterations"]
            if prefs["drive_letter"]:
                self.DRIVE_LETTER = prefs["drive_letter"]
            if was_mounted:
                self.mount()

    def toggle_mount(self):
        if self.is_mounted:
            self.unmount()
        else:
            self.mount()

    def about(self):
        webbrowser.open(self.ABOUT_URL, new=2, autoraise=True)

    def quit(self):
        if self.is_mounted:
            self.unmount()
        sys.exit(0)

    def mount(self):
        try:
            if not os.path.isdir(self.CRYPT_DIR):
                os.makedirs(self.CRYPT_DIR)
            if not os.path.isdir(self.PLAIN_DIR):
                os.makedirs(self.PLAIN_DIR)
        except FileExistsError:
            show_info_dialog(
                QMessageBox.Critical,
                "File Exists!",
                "The provided directory / mountpoint is a file.",
            )
            sys.exit(1)
        self.decrypt()
        if os.name == "nt":
            if os.path.exists(self.DRIVE_LETTER):
                os.system(f"subst {self.DRIVE_LETTER} /d")
            os.system(f"subst {self.DRIVE_LETTER} {self.PLAIN_DIR}")
        if self.OPEN_GUI:
            try:
                webbrowser.open(self.DRIVE_LETTER)
            except AttributeError:
                webbrowser.open(self.PLAIN_DIR)
        self.is_mounted = True
        self.toggle_mount_action.setText("Unmount")

    def unmount(self):
        if os.name == "nt" and os.path.exists(self.DRIVE_LETTER):
            os.system(f"subst {self.DRIVE_LETTER} /d")
        self.write_zip_backup()
        shutil.rmtree(self.CRYPT_DIR)
        os.makedirs(self.CRYPT_DIR)
        self.encrypt()
        shutil.rmtree(self.PLAIN_DIR)
        self.is_mounted = False
        self.toggle_mount_action.setText("Mount")

    # Helper functions #
    def encrypt(self):
        f = Fernet(self.KEY)
        for path, filename in list_files(self.PLAIN_DIR):
            if path == ".":
                encrypted_path = path
            else:
                encrypted_path = f.encrypt(path.encode()).decode()
            if not os.path.isdir(os.path.join(self.CRYPT_DIR, encrypted_path)):
                os.makedirs(os.path.join(self.CRYPT_DIR, encrypted_path))
            if filename == "":
                continue
            with open(os.path.join(self.PLAIN_DIR, path, filename), "rb") as file:
                file_data = file.read()
            encrypted_data = f.encrypt(file_data)
            encrypted_filename = f.encrypt(filename.encode()).decode()
            full_path = os.path.join(self.CRYPT_DIR, encrypted_path, encrypted_filename)
            with open(full_path, "wb") as file:
                file.write(encrypted_data)
            if self.SHRED:
                shred_file(
                    os.path.join(self.PLAIN_DIR, path, filename),
                    self.SHRED_ITERATIONS,
                )

    def decrypt(self):
        f = Fernet(self.KEY)
        for path, filename in list_files(self.CRYPT_DIR):
            try:
                if path == ".":
                    decrypted_path = path
                else:
                    decrypted_path = f.decrypt(path.encode()).decode()
                if not os.path.isdir(os.path.join(self.PLAIN_DIR, decrypted_path)):
                    os.makedirs(os.path.join(self.PLAIN_DIR, decrypted_path))
                if filename == "":
                    continue
                with open(os.path.join(self.CRYPT_DIR, path, filename), "rb") as file:
                    encrypted_data = file.read()
                decrypted_data = f.decrypt(encrypted_data)
                decrypted_filename = f.decrypt(filename.encode()).decode()
            except InvalidToken:
                show_info_dialog(
                    QMessageBox.Critical,
                    "Incorrect key!",
                    "The provided password/keyfile is incorrect.",
                )
                # Cleanup
                if os.path.isdir(self.PLAIN_DIR):
                    shutil.rmtree(self.PLAIN_DIR)
                sys.exit(1)
            full_path = os.path.join(self.PLAIN_DIR, decrypted_path, decrypted_filename)
            with open(full_path, "wb") as file:
                file.write(decrypted_data)

    def write_zip_backup(self):
        with ZipFile(f"{self.CRYPT_DIR}.old.zip", "w") as archive:
            for path, filename in list_files(self.CRYPT_DIR):
                full_path = os.path.join(
                    os.path.relpath(self.CRYPT_DIR), path, filename
                )
                archive.write(full_path)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    window = PyQtCrypt()
    sys.exit(app.exec_())
