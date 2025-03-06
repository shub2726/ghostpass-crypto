import socket
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import threading
import os

KEY_FILE = "server_aes.key" ## for storing documents in encrypted format
def get_server_aes_key():
    """Generate a new AES key if it doesn't exist, otherwise load the existing key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            aes_key = key_file.read()
            if len(aes_key) != 32:  # Validate key length
                raise ValueError("Invalid AES key file. Regenerate the key.")
            return aes_key
    else:
        # Generate a new 256-bit (32-byte) AES key
        aes_key = os.urandom(32)
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(aes_key)
        return aes_key

#server_aes_key = get_server_aes_key()
#iv = os.urandom(16) ### for encrypted filestorage

def get_private_key():
    with open("server_private.key", "rb") as private_file:
        return RSA.import_key(private_file.read())

def recv_all(conn, length):
    """Ensure full data is received."""
    data = b""
    while len(data) < length:
        packet = conn.recv(length - len(data))
        if not packet:
            return None
        data += packet
    return data

def download_handler(conn, addr):
    try:
        print(f"Connection from {addr}")

        # Receive AES key
        private_key = get_private_key()
        rsa_cipher = PKCS1_OAEP.new(private_key)
        
        aes_key_len = struct.unpack("!I", recv_all(conn, 4))[0]
        enc_aes_key = recv_all(conn, aes_key_len)
        aes_key = rsa_cipher.decrypt(enc_aes_key)
        
        # Receive IV
        iv = recv_all(conn, 16)
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

        # Receive encrypted filename
        filename_len = struct.unpack("!Q", recv_all(conn, 8))[0]
        encrypted_filename = recv_all(conn, filename_len)
        filename = unpad(cipher_aes.decrypt(encrypted_filename), AES.block_size).decode()
        print(f"Receiving encrypted file: {filename}")
        
        #file_cipher = AES.new(server_aes_key, AES.MODE_CBC, iv)
        with open(f"received_{filename}", "wb") as file:
            while True:
                encrypted_chunk = conn.recv(4096 + 16)
                if not encrypted_chunk:
                    break
                decrypted_chunk = unpad(cipher_aes.decrypt(encrypted_chunk), AES.block_size)

                if decrypted_chunk == b"END_OF_FILE":
                    print("End of file reached. Closing connection.")
                    break

                file.write(decrypted_chunk)
        
        print(f"File {filename} received and decrypted successfully!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()

def main():
    HOST = "0.0.0.0"
    PORT = 5001

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server_socket.accept()
        print(f"New connection from {addr}")
        client_thread = threading.Thread(target=download_handler, args=(conn, addr), daemon=True)
        client_thread.start()

if __name__ == "__main__":
    main()
