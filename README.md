# Encrypted Vault

A secure file vault application that encrypts multiple files into a single password-protected archive.  Built with Python and Tkinter. 

## Features

- **Multi-File Encryption**: Bundle multiple files into one encrypted vault
- **Strong Encryption**: Uses SHA-256-based key derivation and XOR cipher
- **ZIP Compression**: Files are compressed before encryption to save space
- **Simple Interface**:  Intuitive GUI for managing files and vaults
- **Selective Extraction**: Extract all files or just selected ones from a vault
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

1. Ensure you have Python 3.6+ installed
2. Clone or download this repository
3. Run the application:

```bash
python encrypted_vault.py
```

No additional dependencies required - uses only Python standard library! 

## Usage

### Creating a Vault

1. Click **Add Files...** to select files you want to encrypt
2. Add as many files as you need (they'll appear in the list)
3. Click **Save Vault.. .**
4. Enter a master password and confirm it
5. Choose where to save your `.pvlt` vault file

Your files are now compressed, encrypted, and stored in a single vault file!

### Opening a Vault

1. Click **Open Vault.. .**
2. Select your `.pvlt` vault file
3. Enter the master password
4. The vault contents will be displayed in the list

### Extracting Files from a Vault

After opening a vault: 

1. **(Optional)** Select specific files to extract, or leave none selected to extract all
2. Click **Extract Selected...**
3. Choose the output directory
4. Your files will be decrypted and saved to the chosen location

### Managing the File List

- **Remove Selected**: Remove selected files from the current list
- **Clear List**: Clear all files from the list and reset the vault

## File Format

Vaults are saved with the `.pvlt` extension and contain:
- Header identifier (`PVLT1`)
- Random 16-byte salt (hex-encoded)
- Encrypted ZIP archive (hex-encoded)

The internal structure uses ZIP compression before encryption, so multiple files are bundled efficiently.

## Security Notes

- Each vault uses a random 16-byte salt for key derivation
- Files are compressed into a ZIP archive before encryption
- The encryption uses SHA-256 for key stretching with XOR cipher
- Never share your vault passwords
- Store your `.pvlt` files in a secure location
- This is suitable for personal file protection, not classified information

## Use Cases

- **Secure Backups**: Bundle important documents into encrypted archives
- **File Sharing**: Share multiple files securely with a single password
- **Sensitive Documents**:  Protect financial records, personal documents, etc.
- **Travel Security**: Encrypt important files before storing on cloud or USB drives

## Technical Details

**Encryption Method**:
- Key derivation using SHA-256 with salt
- XOR cipher with derived keystream
- Random salt generated for each vault

**Compression**:
- ZIP compression (DEFLATED method) before encryption
- Reduces vault file size significantly

**File Handling**:
- Original files remain unchanged
- Extracted files are decrypted copies
- No plaintext data stored on disk during vault operations

## Requirements

- Python 3.6 or higher
- tkinter (included with most Python installations)

## Platform Support

- ✅ Windows
- ✅ macOS
- ✅ Linux (with Tk/Tcl support)

## Tips

- Use strong, unique passwords for your vaults
- Keep backups of important vaults in multiple locations
- Remember your passwords - there's no recovery mechanism
- File names are preserved inside the vault
- You can add files with the same name from different directories
