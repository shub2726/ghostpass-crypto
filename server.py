import socket
import json
import rsa
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from database import init_db, store_user, user_exists, verify_user

# Initialize database
init_db()

# Generate RSA key pair (server side)
print("[SERVER] Generating RSA Key Pair (2048 bits)...")
public_key, private_key = rsa.newkeys(2048)
print("[SERVER] RSA Key Pair Generated.")

aes_key = None  # Store AES key once received

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
                        if user_exists(username):
                            response = {"status": "error", "message": "Username already exists"}
                        else:
                            if store_user(username, password):
                                response = {"status": "success", "message": "User registered"}
                            else:
                                response = {"status": "error", "message": "Database error"}

                    elif request["action"] == "login":
                        if verify_user(username, password):
                            response = {"status": "success", "message": "Login successful"}
                        else:
                            response = {"status": "error", "message": "Invalid username or password"}

            client_socket.send(json.dumps(response).encode())

        else:
            response = {"status": "error", "message": "Invalid request"}
            client_socket.send(json.dumps(response).encode())

    except Exception as e:
        print(f"[SERVER] Error: {str(e)}")  # Log error
        client_socket.send(json.dumps({"status": "error", "message": "Server error"}).encode())

    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 12345))
    server.listen(5)
    print("[SERVER] Waiting for connections...")

    while True:
        client_socket, _ = server.accept()
        handle_client(client_socket)

if __name__ == "__main__":
    start_server()
