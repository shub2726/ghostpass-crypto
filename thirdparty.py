import socket
import json
import rsa
import base64
import hmac
import hashlib
import os
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor

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

# CIA Functions
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
        # Forward the docs needed to the client for verification
        docs = ["aadhar", "DL"]
        response = docs
        print(f"[THIRD-PARTY] Asking for {docs}")
        # Send the verification response back to the client
        client_socket.send(json.dumps(response).encode())

        # Connecting with Server to Verify
        # Step 1: Request public key
        response = send_request({"action": "get_public_key"}, "RSA Public Key Request", 12345)
        server_public_key = rsa.PublicKey.load_pkcs1(response["public_key"].encode())
        print("[TP] RSA Public Key Received.")

        # Step 2: Generate AES key
        aes_key = os.urandom(32)  # 256-bit AES key
        print(f"[TP] AES Key Generated: {aes_key.hex()}")

        # Step 3: Encrypt AES key with server's RSA public key
        print("[TP] Encrypting AES Key using RSA...")
        encrypted_aes_key = rsa.encrypt(aes_key, server_public_key)
        print(f"[TP] Encrypted AES Key: {encrypted_aes_key.hex()}")

        # Step 4: Send encrypted AES key to server
        send_request({"action": "send_encrypted_aes", "aes_key": encrypted_aes_key.hex()}, "Encrypted AES Key", 12345)
    
        # Step 5: Send Token to Server and verify token
        token = input("Enter your Token: ")
        response = send_request({"action": "verify_token", "token": token, "docs": docs}, "Token Verification", 12345)
        print("[TP] TOKEN Staus:", response)

        # Send the verification response back to the client
        client_socket.send(json.dumps(response).encode())


def start_third_party_server(host="0.0.0.0", port=6000):
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
