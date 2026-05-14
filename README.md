# 🛡 Amel AES File Encryptor

![Build](https://github.com/NeuraLumina/Amel-AES-File-Encryption/actions/workflows/build.yml/badge.svg)
![Release](https://github.com/NeuraLumina/Amel-AES-File-Encryption/actions/workflows/release.yml/badge.svg)

A desktop file encryption tool built with PyQt6 and AES-256-GCM. Encrypt any file with a password — the original filename is preserved inside the encrypted blob with zero plaintext metadata leakage.

---

## Features

- **AES-256-GCM** authenticated encryption (tamper-evident)
- **PBKDF2-SHA256** key derivation (100 000 iterations, random salt per file)
- **Zero metadata leakage** — filename and file type are encrypted alongside the data
- **Drag-and-drop** or file picker support
- **Non-blocking UI** — encryption/decryption runs on a background thread
- **Safe overwrite handling** — never silently replaces existing files
- **Password visibility toggle**
- Minimum password length enforcement (8 characters)

---

## Requirements

- Python 3.10+
- PyQt6
- cryptography

```bash
pip install PyQt6 cryptography
```

---

## Usage

```bash
python amel_encryptor.py
```

### Encrypting a file

1. Select or drag-and-drop any file onto the window.
2. Enter a password (minimum 8 characters) and confirm it.
3. Click **Encrypt File (.amel)**.
4. The encrypted file is saved alongside the original as `filename.ext.amel`.

### Decrypting a file

1. Select or drag-and-drop a `.amel` file.
2. Enter the password used during encryption.
3. Click **Decrypt File (.amel)**.
4. The original file is restored in the same directory.

> If a file with the output name already exists, the tool automatically appends a counter suffix (e.g. `document_1.pdf`) rather than overwriting.

---

## File Format (v2)

The `.amel` format is a single binary blob:

```
┌─────────────────┬─────────────┬───────────┬──────────────────────────────────────────────────────┐
│  Version        │  Salt       │  Nonce    │  AES-GCM ciphertext                                  │
│  1 byte (0x02)  │  16 bytes   │  12 bytes │  [ name_len 2B ][ filename ][ file data ][ GCM tag ] │
└─────────────────┴─────────────┴───────────┴──────────────────────────────────────────────────────┘
```

Everything after the 29-byte header is ciphertext. The filename, file type, and file contents are all encrypted together as a single plaintext blob — nothing outside the ciphertext reveals anything about the original file.

The 16-byte GCM authentication tag is appended automatically by the `cryptography` library. Decryption raises an exception immediately if the password is wrong or the file has been tampered with.

---

## Security Notes

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-HMAC-SHA256, 100 000 iterations |
| Salt | 16 bytes, `os.urandom` per file |
| Nonce | 12 bytes, `os.urandom` per encryption |
| Authentication | GCM tag verifies integrity on decrypt |
| Metadata leakage | None — filename and type are encrypted |
| Observable at OS level | File size only |
| Minimum password | 8 characters (enforced in UI) |

- **Losing your password means losing the file permanently.** There is no recovery mechanism — this is a feature, not a bug.
- The tool provides **no protection against side-channel attacks** on the host machine. It is designed for file-at-rest encryption, not adversarial environments.
- For very large files, PBKDF2 key derivation may take a moment before progress is visible — this is expected behaviour.

---

## Changelog

### v2 (current)
- Filename and file type are now encrypted inside the ciphertext — zero plaintext metadata in the header
- Added `FORMAT_VERSION` byte (`0x02`) for forward compatibility
- Decrypt rejects files encrypted with an unsupported version rather than producing garbage output
- Removed all inline comments — code is self-explanatory

### v1
- Initial release
- AES-256-GCM encryption with PBKDF2-SHA256 key derivation
- PyQt6 GUI with drag-and-drop support and background thread crypto

---

## License

MIT — use freely, modify freely, attribution appreciated.
