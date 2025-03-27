import socket
import json
import rsa
import os
import base64
import hmac
import hashlib
import datetime
import sys
import time
from Crypto.Cipher import AES
from tqdm import tqdm 

CHUNK_SIZE = 4096  # 4 KB per chunk

def send_request(data, description, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        print(f"[CLIENT] Sending: {description}...")
        client.connect(("127.0.0.1", port))
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

def encrypt_chunk(data, aes_key):
    """Encrypt a chunk using AES-256-GCM"""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode(), base64.b64encode(cipher.nonce).decode()

def send_file(filename, aes_key, file_type, server_ip="127.0.0.1", port=12346):
    """Sends an encrypted file in chunks to the server"""
    if not os.path.exists(filename):
        print("[CLIENT] File not found.")
        return

    print(f"[CLIENT] Sending {filename}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, port))
        
        # Send filename first
        name, ext = os.path.splitext(os.path.basename(filename))
        modified_filename = f"{username}_{file_type}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}{ext}"
        encrypted_filename, nonce_filename = encrypt_chunk(modified_filename.encode(), aes_key)
        hmac_value = hmac.new(aes_key, modified_filename.encode(), hashlib.sha256).hexdigest()
        metadata = {
            "filename": encrypted_filename,
            "nonce": nonce_filename,
            "hmac_value": hmac_value
        }
        client_socket.send((json.dumps(metadata) + "\n").encode())

        start_time = time.time()
        file_size = os.path.getsize(filename)
        sent_bytes = 0
        # Send file data in chunks
        with open(filename, "rb") as f, tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc="Uploading") as pbar:
            while chunk := f.read(CHUNK_SIZE):
                encrypted_chunk, nonce_chunk = encrypt_chunk(chunk, aes_key)
                hmac_value = hmac.new(aes_key, chunk, hashlib.sha256).hexdigest()
                chunk_data = {
                    "chunk": encrypted_chunk,
                    "nonce": nonce_chunk,
                }


                pbar.update(len(chunk))  
                client_socket.send((json.dumps(chunk_data) + "\n").encode())
                time.sleep(0.01)

        # Send completion message
        client_socket.send((json.dumps({"action": "done"}) + "\n").encode())
        print("\n[CLIENT] File sent successfully.")

def request_token(server_ip, server_port, username, docs):
    """Requests a token for a specific document from the server."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    request = {
        "action": "request_token",
        "username": username,
        "docs": docs
    }

    client_socket.send(json.dumps(request).encode())
    
    raw_response = client_socket.recv(4096).decode()  # Read response
    ##print(f"[DEBUG] Raw Response from Server: {repr(raw_response)}")  # Debugging print
    
    if not raw_response.strip():  # Check if empty
        print("[ERROR] Empty response received from server!")
        return None

    response = json.loads(raw_response)  # Parse JSON safely
    client_socket.close()
    
    return response.get("token")

def ask_for_needed_documents(third_party_ip, third_party_port):
    """asks which documents are needed by a third-party for verification."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((third_party_ip, third_party_port))
        request = {"action": "ask_needed_docs"}
        client_socket.send(json.dumps(request).encode())
        response = json.loads(client_socket.recv(4096).decode())
        print(f"[CLIENT] Third-Party Response: {response}")
        return response
    finally:
        client_socket.close()


# Step 1: Request public key
response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 12345)
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
send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex()}, "Encrypted AES Key", 12345)

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
action_response = send_request({
    "action": action,
    "username": encrypted_username,
    "password": encrypted_password,
    "nonce_username": nonce_username,
    "nonce_password": nonce_password,
    "hmac_username": hmac_username,
    "hmac_password": hmac_password
}, f"Encrypted Credentials for {action.capitalize()}", 12345)

documents_uploaded = 0

## Step 8: Upload Docs by Client
documents_uploaded = 0
if action_response["status"] == "success":
    response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 12346)
    file_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
    print("[CLIENT] File server RSA Public Key Received.")
    aadhar_path = None
    dl_path = None
    if action_response["aadhar"] == 0:
        encrypted_aes_key = rsa.encrypt(aes_key, file_public_key)
        response = send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Encrypted AES Key", 12346)
        if (response.get("status") == "ready"):
            aadhar_path = input("Enter path to Aadhar file: ")
            res = send_request({"action": "start_file_upload"}, "Starting file upload", 12346)
            if (res.get("status") == "ready"):
                send_file(aadhar_path, aes_key, "aadhar")
            documents_uploaded += 1
        else:
            print("[CLIENT] Server not ready")
    if action_response["DL"] == 0:
        encrypted_aes_key = rsa.encrypt(aes_key, file_public_key)
        response = send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Encrypted AES Key", 12346)
        if (response.get("status") == "ready"):
            dl_path = input("Enter path to DL file: ")
            res = send_request({"action": "start_file_upload"}, "Starting file upload", 12346)
            if (res.get("status") == "ready"):
                send_file(dl_path, aes_key, "DL")
            documents_uploaded += 1
        else:
            print("[CLIENT] Server not ready")
    if action_response["aadhar"] == 1 and action_response["DL"] == 1:
        print("[CLIENT] Documents are secured.")
        documents_uploaded = 1
else:
    exit(1)

if documents_uploaded == 2:
    send_request({"action": "store_file_details", "aes_key": encrypted_aes_key.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Stored file details", 12346)

third_party_ip = "127.0.0.1"  # Replace with actual third-party IP
third_party_port = 6000  # Replace with actual third-party port
server_ip = "127.0.0.1"
server_port = 12345

## Step 9: Connecting with Third Party
docs = ask_for_needed_documents(third_party_ip, third_party_port)

## Step 10: Token Generation
print(f"Token generation for {docs}")
token = request_token(server_ip, server_port, username, docs)
print("Received Token:", token)


