# PyQtCrypt

[![GitHub license](https://img.shields.io/github/license/Zedeldi/PyQtCrypt?style=flat-square)](https://github.com/Zedeldi/PyQtCrypt/blob/master/LICENSE) [![GitHub last commit](https://img.shields.io/github/last-commit/Zedeldi/PyQtCrypt?style=flat-square)](https://github.com/Zedeldi/PyQtCrypt/commits) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

Cross-platform PyQt5 application, providing an [EncFS](https://github.com/vgough/encfs)-like method for file-based encryption.

## Description

I wrote this program specifically to work on both Windows and GNU/Linux-based systems, predominantly for cloud storage and educational purposes. If you only require Linux support, have a look at [ecryptfs](https://www.ecryptfs.org/). Other great alternatives exist, such as [cryptomator](https://cryptomator.org/) ([GitHub](https://github.com/cryptomator/cryptomator)).

*DISCLAIMER: This code will contain hiccups, and is not efficient for large files. I am not responsible for any data loss.*

### Encryption

PyQtCrypt uses AES symmetric encryption, provided by the [Fernet](https://cryptography.io/en/latest/fernet/) class:

> Fernet is built on top of a number of standard cryptographic primitives. Specifically it uses:
>
>  - [`AES`](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES) in [`CBC`](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC) mode with a 128-bit key for encryption; using [`PKCS7`](https://cryptography.io/en/latest/hazmat/primitives/padding/#cryptography.hazmat.primitives.padding.PKCS7) padding.
>  - [`HMAC`](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/#cryptography.hazmat.primitives.hmac.HMAC) using [`SHA256`](https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#cryptography.hazmat.primitives.hashes.SHA256) for authentication.
>  - Initialization vectors are generated using `os.urandom()`.
>
> For complete details consult the [specification](https://github.com/fernet/spec/blob/master/Spec.md).

### Implementation

When `encrypt()` is called, the following things happen:

1. A backup of the encrypted directory is created
2. The plain directory (or 'mountpoint') is walked; each file / directory's path and data is encrypted
3. If `self.SHRED` is `True`, each file is overwritten `self.SHRED_ITERATIONS` times, and renamed to a random string
4. The plain directory is deleted

The `decrypt()` function should be fairly `self`-explanatory (pun intended).

Encryption is done such that:

- There is only one file per directory (unintended feature of [CBC](https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC) & random IVs, see [Stack Overflow](https://stackoverflow.com/a/55417216) and [Wikipedia](https://en.wikipedia.org/wiki/Probabilistic_encryption))
  - Prevents guessing what each directory contains
- File & directory names are encrypted
  - Paths are encrypted as one name, e.g. foo/bar/baz &#8594; ./gAAAAABfRX... x3
    - Structure of directory trees is hidden
    - Unfortunately, this puts stricter constraints on the length of file names, more so deeper down the stack (see [todo](#todo))

### EncFS

PyQtCrypt is far less complex than [EncFS](https://github.com/vgough/encfs), and has fewer features; it does not handle any filesystem methods, nor actually 'mount' anything. Though [FUSE](https://github.com/libfuse/libfuse) bindings do exist for Python, [python-fuse](https://github.com/libfuse/python-fuse.git) & [fusepy](https://github.com/fusepy/fusepy), implementing such would make programming a cross-platform solution difficult. PyQtCrypt uses [`subst`](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/subst) on Windows to associate a path with a drive letter. On Linux-based operating systems, the plain directory should be treated as a 'mountpoint'.

There are Windows alternatives for EncFS, such as [encfs4win](https://github.com/jetwhiz/encfs4win), which use the [Dokan](https://github.com/dokan-dev/dokany) library for FUSE support.

## Installation

1. Clone this repo: `git clone https://github.com/Zedeldi/PyQtCrypt.git`
2. Install required Python modules: `pip3 install -r requirements.txt`
3. Run: `python3 PyQtCrypt.pyw`

Alternatively, to bundle with [PyInstaller](https://pypi.org/project/pyinstaller/):

1. Install PyInstaller: `pip3 install pyinstaller`
2. Bundle: `pyinstaller [--onefile] --add-data "assets:assets" PyQtCrypt.pyw`
  - Replace "assets:assets" with "assets;assets" on Windows systems, see [os.pathsep](https://docs.python.org/3/library/os.html#os.pathsep)

Libraries:

- [cryptography](https://pypi.org/project/cryptography/) - Fernet, symmetric AES encryption
- [PyQt5](https://pypi.org/project/PyQt5/) - GUI & tray applet

## Todo

- Implement [watchdog](https://pypi.org/project/watchdog/) or periodically backup encrypted directory
- Shorten encrypted file/directory names
  - [Run-length encoding](https://en.wikipedia.org/wiki/Run-length_encoding) may be of some use, see [here](https://codereview.stackexchange.com/a/211099), though repeated patterns are rare

## License

PyQtCrypt is licensed under the GPL v3 for everyone to use, modify and share freely.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

[![GPL v3 Logo](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0-standalone.html)

## Credits

Icon = <https://feathericons.com>

## Donate

If you found this project useful, please consider donating. Any amount is greatly appreciated! Thank you :smiley:

My bitcoin address is: [bc1q5aygkqypxuw7cjg062tnh56sd0mxt0zd5md536](bitcoin://bc1q5aygkqypxuw7cjg062tnh56sd0mxt0zd5md536)
