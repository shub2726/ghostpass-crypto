import socket
import json
import rsa
import os
import base64
import hmac
import hashlib
from Crypto.Cipher import AES

def send_request(data, description):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[CLIENT] Sending: {description}...")
        client.connect(("127.0.0.1", 12345))
        client.send(json.dumps(data).encode())
        response = json.loads(client.recv(4096).decode())
        print(f"[CLIENT] Response: {response}")
        return response
    finally:
        client.close()  # Ensure socket closes properly

def encrypt_aes(plaintext, aes_key):
    """Encrypts data using AES-256-GCM and generates HMAC for integrity"""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext = cipher.encrypt(plaintext.encode())  # No padding needed
    nonce = cipher.nonce

    # Compute HMAC for integrity check
    hmac_value = hmac.new(aes_key, plaintext.encode(), hashlib.sha256).hexdigest()

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(nonce).decode(),
        hmac_value  # Send HMAC along with encrypted data
    )

# Step 1: Request public key
response = send_request({"action": "get_public_key"}, "RSA Public Key Request")
server_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
print("[CLIENT] RSA Public Key Received.")

# Step 2: Generate AES key
aes_key = os.urandom(32)  # 256-bit AES key
print(f"[CLIENT] AES Key Generated: {aes_key.hex()}")

# Step 3: Encrypt AES key with server's RSA public key
print("[CLIENT] Encrypting AES Key using RSA...")
encrypted_aes_key = rsa.encrypt(aes_key, server_public_key)
print(f"[CLIENT] Encrypted AES Key: {encrypted_aes_key.hex()}")

# Step 4: Send encrypted AES key to server
send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex()}, "Encrypted AES Key")

# Step 5: User selects register or login
while True:
    action = input("Choose action: [1] Register [2] Login: ")
    if action in ["1", "2"]:
        action = "register" if action == "1" else "login"
        break
    print("Invalid choice. Please enter 1 or 2.")

# Step 6: Encrypt username & password with AES
username = input("Enter username: ")
password = input("Enter password: ")

print(f"[CLIENT] Encrypting Username '{username}' & Password with AES-256-GCM...")
encrypted_username, nonce_username, hmac_username = encrypt_aes(username, aes_key)
encrypted_password, nonce_password, hmac_password = encrypt_aes(password, aes_key)

# Step 7: Send encrypted credentials to server
send_request({
    "action": action,
    "username": encrypted_username,
    "password": encrypted_password,
    "nonce_username": nonce_username,
    "nonce_password": nonce_password,
    "hmac_username": hmac_username,
    "hmac_password": hmac_password
}, f"Encrypted Credentials for {action.capitalize()}")
