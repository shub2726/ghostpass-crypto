import socket
import json
import os
import base64
import hmac
import hashlib
import rsa
from Crypto.Cipher import AES
from concurrent.futures import ThreadPoolExecutor
from database import update_document_status, store_document_hash

UPLOAD_DIR = "uploads"
CHUNK_SIZE = 4096  # 4 KB per chunk
os.makedirs(UPLOAD_DIR, exist_ok=True)

aes_keys = {}  # Dictionary to store AES keys for users

# Generate RSA Key Pair
print("[SERVER] Generating RSA Key Pair (2048 bits)...")
public_key, private_key = rsa.newkeys(2048)
print("[SERVER] RSA Key Pair Generated.")

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
    
def decrypt_chunk(encrypted_data, nonce, aes_key):
    """Decrypt AES-256-GCM encrypted data"""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(encrypted_data)

def verify_hmac(data, received_hmac, aes_key):
    """Verify HMAC to check data integrity"""
    computed_hmac = hmac.new(aes_key, data.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, received_hmac)

def verify_chunk(data, received_hmac, aes_key):
    computed_hmac = hmac.new(aes_key, data, hashlib.sha256).hexdigest()
    received_hmac_hex = received_hmac.hex()
    return hmac.compare_digest(computed_hmac, received_hmac_hex)

def handle_client(conn, username, aes_key, file, nonce, hmac_received):
    """Receives an encrypted file and stores it after decryption"""
    buffer = ""
    filename = None
    file_path = None

    encrypted_filename = base64.b64decode(file)
    nonce_filename = base64.b64decode(nonce)
    filename = decrypt_chunk(encrypted_filename, nonce_filename, aes_key).decode()
    file_path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
    file_hash = hashlib.sha256()
    if not verify_hmac(filename, hmac_received, aes_key):
        print("f[SERVER] Integrity check not passed")
        return
    
    try:
        print(f"[SERVER] Receiving file: {file_path}")

        os.makedirs(UPLOAD_DIR, exist_ok=True)

        with open(file_path, "wb") as f:
            while True:
                # Keep reading until we get a full JSON object
                while "\n" not in buffer:
                    data = conn.recv(CHUNK_SIZE).decode()
                    if not data:
                        break  # Client disconnected
                    buffer += data

                # Extract JSON message
                if "\n" in buffer:
                    message_json, buffer = buffer.split("\n", 1)
                else:
                    message_json = buffer
                    buffer = ""

                try:
                    chunk_data = json.loads(message_json)
                except json.JSONDecodeError:
                    print("[SERVER] JSON Decode Error. Skipping chunk.")
                    continue

                if chunk_data.get("action") == "done":
                    print(f"[SERVER] Integrity check passed and {filename} received successfully.")
                    break

                encrypted_chunk = base64.b64decode(chunk_data["chunk"])
                nonce_chunk = base64.b64decode(chunk_data["nonce"])
                decrypted_chunk = decrypt_chunk(encrypted_chunk, nonce_chunk, aes_key)
                file_hash.update(decrypted_chunk)
                f.write(decrypted_chunk)
        
        store_document_hash(username, filename, file_hash.hexdigest()) ### store the document hash
    except Exception as e:
        print(f"[SERVER] Error: {str(e)}")
    finally:
        conn.close()

    

def file_server():
    """Handles encrypted file reception on port 12346"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12346))
    server.listen(5)
    print("[SERVER] File server listening on port 12346...")

    with ThreadPoolExecutor(max_workers = 5) as exe:
        while True:
            conn, addr = server.accept()
            print(f"[SERVER] Connection from {addr}")
            data = json.loads(conn.recv(8192).decode())
            
            if "action" in data and data["action"] == "get_public_key":
                print("[SERVER] Client requested RSA Public Key.")
                response = {"public_key": public_key.save_pkcs1().decode()}
                conn.send(json.dumps(response).encode())
                continue
            elif "action" in data and data["action"] == "send_encrypted_aes":
                encrypted_aes_key = bytes.fromhex(data["aes_key"])
                aes_key = rsa.decrypt(encrypted_aes_key, private_key)
                username = decrypt_aes(data["username"], data["nonce_username"], aes_key)
                aes_keys[username] = aes_key  # Store AES key for this user
                print(f"[SERVER] AES key received and stored for user {username}.")
                conn.send(json.dumps({"status": "ready"}).encode())
                continue
            elif "action" in data and data["action"] == "start_file_upload":
                conn.send(json.dumps({"status": "ready"}).encode())
                print("[SERVER] Starting file upload")
                continue
            elif "action" in data and data["action"] == "store_file_details":
                encrypted_aes_key = bytes.fromhex(data["aes_key"])
                aes_key = rsa.decrypt(encrypted_aes_key, private_key)
                username = decrypt_aes(data["username"], data["nonce_username"], aes_key)
                update_document_status(username)
                conn.send(json.dumps({"status": "File details store"}).encode())
                continue
            
            hmac_received = data['hmac_value']
            exe.submit(handle_client, conn, username, aes_key, data['filename'], data['nonce'], hmac_received)
        
if __name__ == "__main__":
    file_server()