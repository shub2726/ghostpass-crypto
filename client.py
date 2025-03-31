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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from database import get_public_key

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

# C,I,A,NR Functions
def load_private_key(private_key_path):
    """Load the private key from a PEM file"""
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def sign_chunk(private_key, data):
    """Sign the data with the private key"""
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def get_public_key_from_db(username):
    """Retrieve the user's public key from the database"""
    # Replace with actual DB call
    public_key_pem = get_public_key(username)  # Fetch PEM format from DB
    return serialization.load_pem_public_key(public_key_pem.encode())

def verify_signature(public_key, signature, data):
    """Verify the signature using the public key"""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

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

def decrypt_aes(ciphertext_b64, nonce_b64, aes_key):
    """Decrypt AES-256-GCM encrypted data"""
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data.decode()
    except Exception as e:
        print(f"[SERVER] Decryption Error: {str(e)}")  # Log internally
        return None  # Return None on error

def verify_hmac(data, received_hmac, aes_key):
    """Verify HMAC to check data integrity"""
    computed_hmac = hmac.new(aes_key, data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, received_hmac)


#Functions for SERVER
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

    private_key = load_private_key("private_key.pem")

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
                signature = sign_chunk(private_key, chunk)
                chunk_data = {
                    "chunk": encrypted_chunk,
                    "nonce": nonce_chunk,
                    "signature": base64.b64encode(signature).decode()
                }


                pbar.update(len(chunk))  
                client_socket.send((json.dumps(chunk_data) + "\n").encode())
                time.sleep(0.001)

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

def generate_key_pair():
    """Generates RSA key pair and stores private key in a PEM file"""
    (public_key, private_key) = rsa.newkeys(2048)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.save_pkcs1())
    return public_key

# Step 1: Request public key
response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 12345)
server_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
print("[CLIENT] RSA Public Key Received.")

# Step 2: Generate AES key
aes_key_server = os.urandom(32)  # 256-bit AES key
print(f"[CLIENT] AES Key Generated: {aes_key_server.hex()}")

# Step 3: Encrypt AES key with server's RSA public key
print("[CLIENT] Encrypting AES Key using RSA...")
encrypted_aes_key_server = rsa.encrypt(aes_key_server, server_public_key)
print(f"[CLIENT] Encrypted AES Key: {encrypted_aes_key_server.hex()}")

# Step 4: Send encrypted AES key to server
send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key_server.hex()}, "Encrypted AES Key", 12345)

# Step 5: User selects register or login
while True:
    action = input("Choose action: [1] Register [2] Login: ")
    if action in ["1", "2"]:
        action = "register" if action == "1" else "login"
        break
    print("Invalid choice. Please enter 1 or 2.")

if action == "register":
    user_public_key = generate_key_pair()
    user_public_key_pem = user_public_key.save_pkcs1().decode()
    print("[CLIENT] Generated public-private key pair for User")

# Step 6: Encrypt username & password with AES
username = input("Enter username: ")
password = input("Enter password: ")

print(f"[CLIENT] Encrypting Username '{username}' & Password with AES-256-GCM...")
encrypted_username, nonce_username, hmac_username = encrypt_aes(username, aes_key_server)
encrypted_password, nonce_password, hmac_password = encrypt_aes(password, aes_key_server)

# Step 7: Send encrypted credentials to server
action_response = None
if action == "register":
    encrypted_public_key, nonce_public_key, hmac_public_key = encrypt_aes(user_public_key_pem, aes_key_server)
    action_response = send_request({
        "action": action,
        "username": encrypted_username,
        "password": encrypted_password,
        "nonce_username": nonce_username,
        "nonce_password": nonce_password,
        "hmac_username": hmac_username,
        "hmac_password": hmac_password,
        "public_key": encrypted_public_key,
        "nonce_public_key": nonce_public_key,
        "hmac_public_key": hmac_public_key
    }, f"Encrypted Credentials for {action.capitalize()}", 12345)
else:
    action_response = send_request({
        "action": action,
        "username": encrypted_username,
        "password": encrypted_password,
        "nonce_username": nonce_username,
        "nonce_password": nonce_password,
        "hmac_username": hmac_username,
        "hmac_password": hmac_password,
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
        encrypted_aes_key_server = rsa.encrypt(aes_key_server, file_public_key)
        response = send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key_server.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Encrypted AES Key", 12346)
        if (response.get("status") == "ready"):
            aadhar_path = input("Enter path to Aadhar file: ")
            res = send_request({"action": "start_file_upload"}, "Starting file upload", 12346)
            if (res.get("status") == "ready"):
                send_file(aadhar_path, aes_key_server, "aadhar")
            documents_uploaded += 1
        else:
            print("[CLIENT] Server not ready")
    if action_response["DL"] == 0:
        encrypted_aes_key_server= rsa.encrypt(aes_key_server, file_public_key)
        response = send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key_server.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Encrypted AES Key", 12346)
        if (response.get("status") == "ready"):
            dl_path = input("Enter path to DL file: ")
            res = send_request({"action": "start_file_upload"}, "Starting file upload", 12346)
            if (res.get("status") == "ready"):
                send_file(dl_path, aes_key_server, "DL")
            documents_uploaded += 1
        else:
            print("[CLIENT] Server not ready")
    if action_response["aadhar"] == 1 and action_response["DL"] == 1:
        print("[CLIENT] Documents are secured.")
        documents_uploaded = 1
else:
    exit(1)

if documents_uploaded == 2:
    send_request({"action": "store_file_details", "aes_key": encrypted_aes_key_server.hex(), "username": encrypted_username, "nonce_username": nonce_username}, "Stored file details", 12346)


# Third Party Communication
# Step 1: Request public key
response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 6000)
thirdparty_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
print("[CLIENT][THIRD-PARTY] RSA Public Key Received.")

# Step 2: Generate AES key
aes_key = os.urandom(32)  # 256-bit AES key
print(f"[CLIENT][THIRD-PARTY] AES Key Generated: {aes_key.hex()}")

# Step 3: Encrypt AES key with third party's RSA public key
print("[CLIENT][THIRD-PARTY] Encrypting AES Key using RSA...")
encrypted_aes_key = rsa.encrypt(aes_key, thirdparty_public_key)
print(f"[CLIENT][THIRD-PARTY] Encrypted AES Key: {encrypted_aes_key.hex()}")

# Step 4: Send encrypted AES key to third party
send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex()}, "Encrypted AES Key", 6000)

# Step 5: Connecting with Third Party
response = send_request({"action": "ask_needed_docs"}, "Ask Documents", 6000)

# Extract encrypted values
encrypted_docs = response["encrypted_docs"]
nonce_docs = response["nonce"]
received_hmac = response["hmac"]

# Decrypt the data
decrypted_docs = decrypt_aes(encrypted_docs, nonce_docs, aes_key)

if decrypted_docs:
    # Verify HMAC on the decrypted text
    if verify_hmac(decrypted_docs, received_hmac, aes_key):
        docs = json.loads(decrypted_docs)  # Convert JSON string back to list
        print(f"[CLIENT] Received required docs: {docs}")
    else:
        print("[CLIENT] HMAC verification failed! Rejecting data.")
else:
    print("[CLIENT] Decryption failed!")


# Server Communication #2
## Step 1: Token Generation
encrypted_username, nonce_username, hmac_username = encrypt_aes(username, aes_key_server)
encrypted_docs, nonce_docs, hmac_docs = encrypt_aes(json.dumps(docs), aes_key_server)

response = send_request({
    "action": "request_token",
    "username": encrypted_username,
    "nonce_username": nonce_username,
    "hmac_username": hmac_username,
    "docs": encrypted_docs,
    "nonce_docs": nonce_docs,
    "hmac_docs": hmac_docs
}, "Request Token", 12345)

# Extract encrypted values
encrypted_token = response["token"]
nonce_token = response["nonce_token"]
hmac_token = response["hmac_token"]

# Decrypt the data
decrypted_token = decrypt_aes(encrypted_token, nonce_token, aes_key_server)

if decrypted_token:
    # Verify HMAC on the decrypted text
    if verify_hmac(decrypted_token, hmac_token, aes_key_server):
        print(f"[CLIENT] Received Token: {decrypted_token}")
    else:
        print("[CLIENT] HMAC verification failed! Rejecting data.")
else:
    print("[CLIENT] Decryption failed!")