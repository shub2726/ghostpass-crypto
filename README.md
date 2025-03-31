# GhostPass: Tokenization System for Secure ID Verification

## Overview
GhostPass is a secure ID verification system that allows users to authenticate and share verification tokens without exposing their actual data. It uses encryption, hashing, and digital signatures to ensure privacy, integrity, and authenticity.

## Features
- **Secure User Authentication**: Passwords are hashed for protection.
- **Encrypted Document Storage**: Ensures confidentiality and integrity.
- **Token-Based Verification**: Uses HMAC and digital signatures.
- **Privacy-Preserving Verification**: Third parties can verify identities without accessing actual documents.

## Prerequisites
Ensure you have **Python 3.8+** installed along with the required dependencies.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/ghostpass.git
   cd ghostpass
   ```
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Execution Steps
### 1. Start the Upload Server
Handles encrypted document uploads.
   ```bash
   python upload_server.py
   ```

### 2. Start the GhostPass Server
Manages authentication, encryption, and tokenization.
   ```bash
   python server.py
   ```

### 3. Start the Client
Registers users, uploads documents, and requests verification tokens.
   ```bash
   python client.py
   ```

### 4. Start the Third-Party Service
Verifies tokens and grants/denies access.
   ```bash
   python third_party.py
   ```

## System Flow
1. User registers and logs in.
2. User uploads encrypted documents.
3. User requests a verification token.
4. Server generates and signs the token.
5. User shares the token with a third party.
6. The third party sends the token to the server for verification.
7. Server verifies the token and responds to the third party.
8. The third party grants or denies access to the user.

## Security Mechanisms
- **Password Hashing**: SHA-256
- **Encryption**: AES-256 for document storage
- **Integrity Check**: HMAC-SHA256 for tokens
- **Digital Signatures**: RSA-2048 for authentication

## Notes
- Ensure all servers are running before executing the client.
- Tokens are time-sensitive and expire after a predefined duration.
- Modify `config.py` for custom security parameters.

## License
This project is licensed under the **MIT License**.

