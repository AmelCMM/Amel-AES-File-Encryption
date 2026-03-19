# 🛡 Amel AES File Encryptor

A desktop file encryption tool built with PyQt6 and AES-256-GCM. Encrypt any file with a password and decrypt it later — the original filename is preserved inside the encrypted blob.

---

## Features

- **AES-256-GCM** authenticated encryption (tamper-evident)
- **PBKDF2-SHA256** key derivation (100 000 iterations, random salt per file)
- **Drag-and-drop** or file picker support
- **Non-blocking UI** — encryption/decryption runs on a background thread
- **Safe overwrite handling** — never silently replaces existing files
- **Filename preservation** — original name is stored inside the `.amel` file
- **Password visibility toggle**
- Minimum password length enforcement (8 characters)

---

## Requirements

- Python 3.10+
- PyQt6
- cryptography

Install dependencies:

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

## File Format

The `.amel` format is a single binary blob with the following layout:

```
┌─────────────┬───────────────┬────────────────────┬──────────────────────┬─────────────────────────┐
│  Salt       │  Nonce        │  Name length        │  Original filename   │  AES-GCM ciphertext     │
│  16 bytes   │  12 bytes     │  2 bytes (big-end)  │  variable            │  variable + 16-byte tag │
└─────────────┴───────────────┴────────────────────┴──────────────────────┴─────────────────────────┘
```

The 16-byte GCM authentication tag is appended to the ciphertext by the `cryptography` library automatically. Decryption will raise an exception if the password is wrong or the file has been tampered with.

---

## Security Notes

| Property | Detail |
|---|---|
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-HMAC-SHA256, 100 000 iterations |
| Salt | 16 bytes, `os.urandom` per file |
| Nonce | 12 bytes, `os.urandom` per encryption |
| Authentication | GCM tag verifies integrity on decrypt |
| Minimum password | 8 characters (enforced in UI) |

- **Losing your password means losing the file.** There is no recovery mechanism.
- The tool provides **no protection against side-channel attacks** on the host machine — it is designed for file-at-rest encryption, not adversarial environments.
- For very large files (several GB), PBKDF2 key derivation may take a second or two before progress is visible — this is normal.

---

## Changes from v1

| # | Fix |
|---|-----|
| 1 | Progress bar now resets to 0 before every operation |
| 2 | File path stored in `self.file_path`, not parsed from label text |
| 3 | Output files are auto-renamed if destination already exists |
| 4 | Crypto runs on a `QThread` — UI never freezes |
| 5 | Status label shows "Encrypting…" / "Decrypting…" during operation |
| 6 | Buttons disabled during operation, re-enabled on completion |
| 7 | Removed deprecated `default_backend()` from PBKDF2HMAC call |
| 8 | Replaced surrogate-pair emoji with literal `🛡` character |
| 9 | Minimum password length of 8 characters enforced with clear warning |

---

## License

MIT — use freely, modify freely, attribute appreciated.
