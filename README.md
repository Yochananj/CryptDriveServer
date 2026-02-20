<img width="296" height="256" alt="icon" src="https://github.com/user-attachments/assets/cd4bb9d5-06c9-404d-8ef5-f09261e0ed28" />

# CryptDrive

**Cyber 2025-26 Final Project - © Yochanan Julian**

A secure, encrypted cloud storage solution with client-server architecture. CryptDrive provides end-to-end encryption
for file storage and management with a focus on security and privacy.

## 🚀 Features

- **Secure Authentication**: User sign-up and login with password hashing and salt
- **End-to-End Encryption**: All files are encrypted using AES with user-specific master keys
- **File Management**:
    - Create, download, delete, rename, and move files
    - Directory operations (create, delete, rename, move)
    - Hierarchical file system navigation
- **AES Encryption**: Secure client-server communication using public-key cryptography using .X25519
- **User Account Management**: Change username and password with automatic re-encryption

## 📋 Requirements

- Python 3.7+
- Dependencies listed in `modules.txt`

## 🔧 Installation

### Windows (PowerShell)
1. Download and extract the zip file containing the repository.
2. Execute the PowerShell script:
```powershell
install.ps1
```

### MacOS (Shell Script)
1. Download and extract the zip file containing the repository.
2. Open the terminal in the project directory and execute this shell script:
```shell
chmod +x install.sh
./install.sh
```

