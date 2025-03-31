import socket
import json
import rsa
import base64
import hmac
import hashlib
import os
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from database import get_public_key

# Generate RSA key pair (server side)
print("[SERVER] Generating RSA Key Pair (2048 bits)...")
public_key, private_key = rsa.newkeys(2048)
print("[SERVER] RSA Key Pair Generated.")

aes_key = None  # Store AES key once received

# Send Request
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

def verify_signn(public_key, signature, data):
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

def verify_sign(data, received_hmac, aes_key):
    """Verify HMAC to check data integrity"""
    computed_hmac = hmac.new(aes_key, data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, received_hmac)


# Main Client Handling
def handle_third_party_request(client_socket):
    global aes_key
    """Handles a token verification request from the client."""
    request = json.loads(client_socket.recv(4096).decode())

    if request["action"] == "get_public_key":
        print("[THIRD PARTY] Client requested RSA Public Key.")
        response = {"public_key": public_key.save_pkcs1().decode()}
        client_socket.send(json.dumps(response).encode())

    elif request["action"] == "send_encrypted_aes":
        print("[THIRD PARTY] Received Encrypted AES Key from Client.")
        encrypted_aes_key = bytes.fromhex(request.get("aes_key"))
            
        # Decrypt AES key using RSA private key
        aes_key = rsa.decrypt(encrypted_aes_key, private_key)
        print(f"[THIRD PARTY] AES Key Decrypted: {aes_key.hex()}")

        response = {"status": "success", "message": "AES key received"}
        client_socket.send(json.dumps(response).encode())

    elif request["action"] == "ask_needed_docs":
        # Telling Client the documents to base token off.
        # List of documents needed
        docs = ["aadhar", "DL"]
        # Convert list to JSON string (AES encrypts text, not lists)
        docs_str = json.dumps(docs)
        # Encrypt docs using AES
        encrypted_docs, nonce_docs, hmac_docs = encrypt_aes(docs_str, aes_key)
        print(f"[THIRD-PARTY] Asking for documents (Encrypted)")

        # Send encrypted data
        response = {
            "encrypted_docs": encrypted_docs,
            "nonce": nonce_docs,
            "hmac": hmac_docs  # Already generated in encrypt_aes()
        }
        client_socket.send(json.dumps(response).encode())

        # Connecting with Server to Verify
        # Step 1: Request public key
        response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 12345)
        server_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
        print("[TP] RSA Public Key Received.")

        # Step 2: Generate AES key
        aes_key_server = os.urandom(32)  # 256-bit AES key
        print(f"[TP] AES Key Generated: {aes_key_server.hex()}")

        # Step 3: Encrypt AES key with server's RSA public key
        print("[TP] Encrypting AES Key using RSA...")
        encrypted_aes_key_server = rsa.encrypt(aes_key_server, server_public_key)
        print(f"[TP] Encrypted AES Key: {encrypted_aes_key_server.hex()}")

        # Step 4: Send encrypted AES key to server
        send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key_server.hex()}, "Encrypted AES Key", 12345)
    
        # Step 5: Send Token to Server and verify token
        token = input("Enter your Token: ")
        docs_str = json.dumps(docs)
        encrypted_docs, nonce_docs, hmac_docs = encrypt_aes(docs_str, aes_key_server)
        encrypted_token, nonce_token, hmac_token = encrypt_aes(token, aes_key_server)

        response = send_request({
            "action": "verify_token",
            "token": encrypted_token,
            "nonce_token": nonce_token,
            "hmac_token": hmac_token,
            "docs": encrypted_docs,
            "nonce_docs": nonce_docs,
            "hmac_docs": hmac_docs
        }, "Request Token", 12345)

        # Extract encrypted values
        encrypted_status = response["encrypted_status"]
        nonce_status = response["nonce_status"]
        hmac_status = response["hmac_status"]

        # Decrypt the data
        decrypted_status = decrypt_aes(encrypted_status, nonce_status, aes_key_server)

        if decrypted_status:
            # Verify sign on the decrypted text
            if verify_sign(decrypted_status, hmac_status, aes_key_server):
                print(f"[TP] Received Status: {decrypted_status}")
            else:
                print("[TP] Signature verification failed! Rejecting data.")
        else:
            print("[TP] Decryption failed!")
        # Step 6: Send the verification response back to the client [Did NOT Complete]
        client_socket.send(json.dumps(response).encode())


def start_third_party_server(host="127.0.0.1", port=6000):
    """Starts the third-party verification server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[THIRD-PARTY] Waiting for clients...")

    with ThreadPoolExecutor(max_workers = 5) as exe:
        while True:
            client_socket, _ = server.accept()
            ### add multithreading and uploading module
            exe.submit(handle_third_party_request, client_socket)

# Start the third-party server
start_third_party_server()
