import socket
import json
import rsa
import base64
import hmac
import hashlib
import os
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor
from database import init_db, store_user, user_exists, verify_user
import datetime
from datetime import timezone
import jwt  

SECRET_KEY = "super_secret_key"  # Change this in production
UPLOAD_DIR = "uploads"

# Initialize database
init_db()

# Generate RSA key pair (server side)
print("[SERVER] Generating RSA Key Pair (2048 bits)...")
public_key, private_key = rsa.newkeys(2048)
print("[SERVER] RSA Key Pair Generated.")

# CIA Functions
aes_key = None  # Store AES key once received

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


# THIRD-Party Functions
token_store = {}  # Temporary storage in memory

def generate_token(username, docs):
    """Generates a token and stores it temporarily with document info."""
    user_files = [
        f for f in os.listdir("uploads") 
        if any(f.startswith(f"{username}_{doc}_") for doc in docs)
    ]

    if not user_files:
        return None  # No matching documents found

    payload = {
        "username": username,
        "documents": docs,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(seconds=15)
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    
    # Store the token temporarily in memory
    token_store[token] = {
        "username": username,
        "documents": docs,
        "expiry": datetime.datetime.now(timezone.utc) + datetime.timedelta(seconds=15)
    }
    
    return token

def verify_token(token, docs):
    """Verifies token validity and ensures requested docs match the stored ones."""
    if token not in token_store:
        return {"status": "invalid", "message": "Token not found"}

    stored_data = token_store[token]
    original_docs = stored_data["documents"]
    
    # Ensure requested docs are a subset of original docs
    if not docs == original_docs:
        return {"status": "invalid", "message": "Unauthorized document request"}

    # Check expiry
    if datetime.datetime.now(timezone.utc) > stored_data["expiry"]:
        return {"status": "expired", "message": "Token expired"}

    return {"status": "valid", "username": stored_data["username"], "documents": original_docs}


# Main Handling of Clients
def handle_client(client_socket):
    global aes_key
    try:
        data = client_socket.recv(4096).decode()
        request = json.loads(data)

        if request.get("action") == "get_public_key":
            print("[SERVER] Client requested RSA Public Key.")
            response = {"public_key": public_key.save_pkcs1().decode()}
            client_socket.send(json.dumps(response).encode())

        elif request.get("action") == "send_encrypted_aes":
            print("[SERVER] Received Encrypted AES Key from Client.")
            encrypted_aes_key = bytes.fromhex(request.get("aes_key"))
            
            # Decrypt AES key using RSA private key
            aes_key = rsa.decrypt(encrypted_aes_key, private_key)
            print(f"[SERVER] AES Key Decrypted: {aes_key.hex()}")

            response = {"status": "success", "message": "AES key received"}
            client_socket.send(json.dumps(response).encode())

        elif request.get("action") in ["register", "login"]:
            if aes_key is None:
                response = {"status": "error", "message": "AES key not set"}
            else:
                print(f"[SERVER] Received Encrypted {request['action'].capitalize()} Request.")

                # Decrypt username & password
                username = decrypt_aes(request["username"], request["nonce_username"], aes_key)
                password = decrypt_aes(request["password"], request["nonce_password"], aes_key)

                # Verify HMAC integrity
                if not username or not password:
                    response = {"status": "error", "message": "Decryption failed"}
                elif not verify_hmac(username, request["hmac_username"], aes_key) or not verify_hmac(password, request["hmac_password"], aes_key):
                    response = {"status": "error", "message": "Integrity check failed"}
                else:
                    print(f"[SERVER] Decrypted Username: {username}")
                    print(f"[SERVER] Decrypted Password: {password}")

                    if request["action"] == "register":
                        user_obj = user_exists(username)
                        if user_obj:
                            print(user_obj)
                            aadhar_check = user_obj[3]
                            DL_check = user_obj[4]
                            response = {"status": "error", "message": "Username already exists", "aadhar": aadhar_check, "DL": DL_check}
                        else:
                            user_public_key = decrypt_aes(request["public_key"], request["nonce_public_key"], aes_key)
                            if store_user(username, password, user_public_key):
                                response = {"status": "success", "message": "User registered", "aadhar": 0, "DL": 0}
                            else:
                                response = {"status": "error", "message": "Database error"}

                    elif request["action"] == "login":
                        if verify_user(username, password):
                            user_obj = user_exists(username)
                            aadhar_check = user_obj[3]
                            DL_check = user_obj[4]
                            response = {"status": "success", "message": "Login successful", "aadhar": aadhar_check, "DL": DL_check}
                        else:
                            response = {"status": "error", "message": "Invalid username or password"}

            client_socket.send(json.dumps(response).encode())


        elif request["action"] == "request_token":
            encrypted_username = request["username"]
            nonce_username = request["nonce_username"]
            hmac_username = request["hmac_username"]
            encrypted_docs = request["docs"]
            nonce_docs = request["nonce_docs"]
            hmac_docs = request["hmac_docs"]

            # Decrypt username
            username = decrypt_aes(encrypted_username, nonce_username, aes_key)

            # Verify HMAC for username
            if username is None or not verify_hmac(username, hmac_username, aes_key):
                response = {"status": "error", "message": "Authentication failed"}
            
            else:
                # Decrypt documents
                docs_json = decrypt_aes(encrypted_docs, nonce_docs, aes_key)
                
                # Verify HMAC for documents
                if docs_json is None or not verify_hmac(docs_json, hmac_docs, aes_key):
                    response = {"status": "error", "message": "Document integrity verification failed"}
                else:
                    docs = json.loads(docs_json)
                    token = generate_token(username, docs)
                    
                    # Encrypt the token before sending
                    encrypted_token, nonce_token, hmac_token = encrypt_aes(token, aes_key)

                    response = {
                        "status": "success",
                        "token": encrypted_token,
                        "nonce_token": nonce_token,
                        "hmac_token": hmac_token
                    }
            
            print(f"[SERVER] Sending encrypted response.")
            response_json = json.dumps(response)
            client_socket.send(response_json.encode())



        elif request["action"] == "verify_token":
            print("[SERVER] Received 'verify_token' request.")
            encrypted_token = request["token"]
            nonce_token = request["nonce_token"]
            hmac_token = request["hmac_token"]

            encrypted_docs = request["docs"]
            nonce_docs = request["nonce_docs"]
            hmac_docs = request["hmac_docs"]

            print("[SERVER] Received encrypted token for verification.")

            # Decrypt the token
            decrypted_token = decrypt_aes(encrypted_token, nonce_token, aes_key)
            print(f"[SERVER] Decrypted Token: {decrypted_token}")

            if decrypted_token is None:
                print("[SERVER] Token decryption failed!")
                response = {"status": "error", "message": "Token decryption failed"}

            elif not verify_hmac(decrypted_token, hmac_token, aes_key):
                print("[SERVER] HMAC verification failed for token!")
                response = {"status": "error", "message": "Token integrity verification failed"}

            else:
                print("[SERVER] Token decrypted and HMAC verified.")

                # Decrypt the documents
                docs_json = decrypt_aes(encrypted_docs, nonce_docs, aes_key)
                print(f"[SERVER] Decrypted Docs: {docs_json}")

                if docs_json is None:
                    print("[SERVER] Document decryption failed!")
                    response = {"status": "error", "message": "Document decryption failed"}

                elif not verify_hmac(docs_json, hmac_docs, aes_key):
                    print("[SERVER] HMAC verification failed for documents!")
                    response = {"status": "error", "message": "Document integrity verification failed"}

                else:
                    docs = json.loads(docs_json)
                    print(f"[SERVER] Docs after JSON load: {docs}")

                    # Verify the token
                    token_data = verify_token(decrypted_token, docs)
                    print(f"[SERVER] Token verification result: {token_data}")

                    if token_data["status"] == "valid":
                        response = {"status": "valid"}
                    else:
                        response = {"status": token_data["status"], "message": token_data["message"]}

            response_json = json.dumps(response)
            # Encrypt the response
            encrypted_status, nonce_status, hmac_status = encrypt_aes(response_json, aes_key)

            # Send encrypted response
            response_packet = json.dumps({
                "encrypted_status": encrypted_status,
                "nonce_status": nonce_status,
                "hmac_status": hmac_status
            })

            print(f"[SERVER] Sending Encrypted Response: {response_packet}")  # Debugging print
            client_socket.send(response_packet.encode())  # Send the encrypted response



        else:
            response = {"status": "error", "message": "Invalid request"}
            client_socket.send(json.dumps(response).encode())

        
    except Exception as e:
        print(f"[SERVER] Error: {str(e)}")  # Log error
        client_socket.send(json.dumps({"status": "error", "message": "Server error"}).encode())

    finally:
        client_socket.close()


def start_server():
    """Starts the server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("[SERVER] Waiting for connections...")

    with ThreadPoolExecutor(max_workers = 5) as exe:
        while True:
            client_socket, _ = server.accept()
            ### add multithreading and uploading module
            exe.submit(handle_client, client_socket)

if __name__ == "__main__":
    start_server()
