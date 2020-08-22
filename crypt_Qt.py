import base64, hashlib, os, random, shutil, string, sys, webbrowser
from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtCore import *
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import *
from zipfile import ZipFile

"""

Description:
 - Encryption:
   - Only one file per directory
     - Prevents guessing what each directory contains
   - File & directory names are encrypted
     - Directory trees are encrypted as one name, e.g. foo/bar/baz -> gAAAAABfPsVy...
       - Number of subdirectories is hidden
       - Unfortunately, this puts stricter constraints on the length of file names
   - Empty directories are not saved, though this can easily be done


TODO
----
Re-write using Qt
 - QFileDialog <--
 - Export helper functions to utils.py, and pass args
 - Tidy classes
   - Merge settings with main class?

Keep empty directories

Add logging, argparse

Watchdog

"""

def gen_key():
	filename=''.join(random.choice(string.ascii_uppercase) for _ in range(8))+".key"
	key = Fernet.generate_key()
	with open(filename, "wb") as key_file:
		key_file.write(key)
	return key, filename

def list_files(directory):
	files = []
	for (dirpath, subdirs, filenames) in os.walk(directory):
		files.extend([[os.path.relpath(dirpath, start=directory), f] for f in filenames]) # Note: this only saves directories with files
	return files

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
	if file_dialog.exec_(): return file_dialog.selectedFiles()[0]

class SettingsDialog(QDialog):
	def __init__(self):
		super().__init__()
		
		self.key = None
		self.drive_letter = None
		
		self.setWindowTitle("PyQt Crypt - Enter password")
		self.resize(300, 100)
		
		self.text_pass = QLineEdit(self)
		self.text_pass.setPlaceholderText("Password (leave blank to generate)")
		self.text_pass.setEchoMode(QLineEdit.Password)
		self.button_keyfile = QPushButton("Keyfile", self)
		self.button_submit = QPushButton("Submit", self)
		self.text_pass.returnPressed.connect(self.read_password)
		self.button_keyfile.clicked.connect(self.read_keyfile)
		self.button_submit.clicked.connect(self.return_prefs)
		
		self.main_layout = QVBoxLayout()
		self.opt_layout = QHBoxLayout()
		
		self.opt_layout.addWidget(self.button_keyfile)
		
		self.main_layout.addWidget(self.text_pass)
		self.main_layout.addLayout(self.opt_layout)
		self.main_layout.addWidget(self.button_submit)
		
		self.setLayout(self.main_layout)
		
		## Windows only ##
		if os.name == 'nt':
			self.drive_letter_selector = QComboBox()
			self.drive_letter_selector.addItems(map(lambda l : l + ':', list(string.ascii_lowercase)))
			self.drive_letter_selector.setCurrentIndex(25)
			self.drive_letter_selector.currentIndexChanged.connect(self.set_drive_letter)
			self.opt_layout.addWidget(self.drive_letter_selector)
			self.set_drive_letter()
	
	def read_password(self):
		if self.text_pass.text() == "":
			self.key, filename=gen_key()
			show_info_dialog(QMessageBox.Information, "Keyfile Saved", "Your keyfile has been saved at {0}.".format(filename))
		else: self.key=base64.urlsafe_b64encode(hashlib.sha256(self.text_pass.text().encode()).digest())
		self.return_prefs()
	
	def read_keyfile(self):
		keyfile = QFileDialog.getOpenFileName(self, "Open keyfile")[0]
		try: self.key=open(keyfile, "rb").read()
		except OSError: self.key=None
		self.return_prefs()
	
	def set_drive_letter(self):
		self.drive_letter=self.drive_letter_selector.currentText()
	
	def return_prefs(self):
		self.accept()
		return {"key": self.key, "drive_letter": self.drive_letter}

	@staticmethod
	def get_prefs():
		dialog = SettingsDialog()
		dialog.exec_()
		return dialog.return_prefs()

class PyQtCrypt(QSystemTrayIcon):
	def __init__(self):
		super().__init__()
		
		## Default settings ##
		self.KEY=None
		self.CRYPT_DIR=os.path.abspath("crypt_dir")
		self.PLAIN_DIR=os.path.abspath("plain_dir")
		self.OPEN_GUI=False
		
		self.set_prefs()
		if self.KEY == None: sys.exit(1) # No key received, cancelled
		
		self.initUI()
		self.mount()
	
	def initUI(self):
		self.setIcon(QIcon("briefcase.svg"))
		self.setVisible(True)
		self.setContextMenu(self.build_menu())
		self.activated.connect(self.on_activated)
		
	def build_menu(self):
		menu=QMenu()
		self.toggle_mount_action=QAction("Unmount", self)
		self.toggle_mount_action.triggered.connect(self.toggle_mount)
		menu.addAction(self.toggle_mount_action)
		settings_action=QAction("Settings", self)
		settings_action.triggered.connect(self.set_prefs)
		menu.addAction(settings_action)
		menu.addSeparator()
		quit_action=QAction("Quit", self)
		quit_action.triggered.connect(lambda: sys.exit(0))
		menu.addAction(quit_action)
		return menu
	
	def on_activated(self, reason):
		if reason == QSystemTrayIcon.Trigger:
			self.toggle_mount()
		elif reason == QSystemTrayIcon.MiddleClick:
			self.set_prefs()
	
	def set_prefs(self):
		if (prefs := SettingsDialog.get_prefs()):
			if prefs["key"]: self.KEY=prefs["key"]
			if prefs["drive_letter"]: self.DRIVE_LETTER=prefs["drive_letter"]
	
	def toggle_mount(self):
		if os.path.isdir(self.PLAIN_DIR):
			self.unmount()
			self.toggle_mount_action.setText("Mount")
		else:
			self.mount()
			self.toggle_mount_action.setText("Unmount")
	
	def mount(self):
		if not os.path.isdir(self.CRYPT_DIR): os.makedirs(self.CRYPT_DIR)
		if not os.path.isdir(self.PLAIN_DIR): os.makedirs(self.PLAIN_DIR)
		self.decrypt()
		if os.name == 'nt':
			if os.path.exists(self.DRIVE_LETTER): os.system("subst {0} /d".format(self.DRIVE_LETTER))
			os.system("subst {0} {1}".format(self.DRIVE_LETTER, self.PLAIN_DIR))
		if self.OPEN_GUI:
			try: webbrowser.open(self.DRIVE_LETTER)
			except NameError: webbrowser.open(self.PLAIN_DIR)

	def unmount(self):
		if os.name == 'nt' and os.path.exists(self.DRIVE_LETTER): os.system("subst {0} /d".format(self.DRIVE_LETTER))
		self.write_zip_backup()
		shutil.rmtree(self.CRYPT_DIR)
		os.makedirs(self.CRYPT_DIR)
		self.encrypt()
		shutil.rmtree(self.PLAIN_DIR)
	
	## Helper functions ##
	def encrypt(self):
		f = Fernet(self.KEY)
		for path, filename in list_files(self.PLAIN_DIR):
			with open(os.path.join(self.PLAIN_DIR, path, filename), "rb") as file:
				file_data = file.read()
			encrypted_data = f.encrypt(file_data)
			if path == '.': encrypted_path=path
			else: encrypted_path = f.encrypt(path.encode()).decode()
			encrypted_filename = f.encrypt(filename.encode()).decode()
			if not os.path.isdir(os.path.join(self.CRYPT_DIR, encrypted_path)): os.makedirs(os.path.join(self.CRYPT_DIR, encrypted_path))
			with open(os.path.join(self.CRYPT_DIR, encrypted_path, encrypted_filename), "wb") as file:
				file.write(encrypted_data)

	def decrypt(self):
		f = Fernet(self.KEY)
		for path, filename in list_files(self.CRYPT_DIR):
			with open(os.path.join(self.CRYPT_DIR, path, filename), "rb") as file:
				encrypted_data = file.read()
			try:
				decrypted_data = f.decrypt(encrypted_data)
				if path == '.': decrypted_path=path
				else: decrypted_path = f.decrypt(path.encode()).decode()
				decrypted_filename = f.decrypt(filename.encode()).decode()
			except InvalidToken:
				show_info_dialog(QMessageBox.Critical, "Incorrect key!", "The provided password/keyfile is invalid.")
				sys.exit(1)
			if not os.path.isdir(os.path.join(self.PLAIN_DIR, decrypted_path)): os.makedirs(os.path.join(self.PLAIN_DIR, decrypted_path))
			with open(os.path.join(self.PLAIN_DIR, decrypted_path, decrypted_filename), "wb") as file:
				file.write(decrypted_data)
	
	def write_zip_backup(self):
		with ZipFile('encrypted_files.old.zip','w') as archive:
			for path, filename in list_files(self.CRYPT_DIR):
				archive.write(os.path.join(os.path.relpath(self.CRYPT_DIR), path, filename))

if __name__ == "__main__":
	app = QApplication(sys.argv)
	app.setQuitOnLastWindowClosed(False)
	window = PyQtCrypt()
	sys.exit(app.exec_())
