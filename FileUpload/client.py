import socket
import struct
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Get the public key from server
def get_public_key():
    with open("server_public.pem", "rb") as public_file:
        return RSA.import_key(public_file.read())

# Function to encrypt filename and file contents
def upload_handler(client_socket, filename, aes_key, iv):
    try:
        file_size = os.path.getsize(filename)
        with open(filename, "rb") as file:
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

            # Encrypt and send filename
            filename_bytes = filename.encode()
            encrypted_filename = cipher_aes.encrypt(pad(filename_bytes, AES.block_size))
            client_socket.sendall(struct.pack("!Q", len(encrypted_filename)) + encrypted_filename)

            # Encrypt and send file in chunks
            bytes_sent = 0
            while chunk := file.read(4096):
                encrypted_chunk = cipher_aes.encrypt(pad(chunk, AES.block_size))
                client_socket.sendall(encrypted_chunk)
                bytes_sent += len(chunk)
                progress = (bytes_sent / file_size) * 100
                print(f"\rUploading: {progress:.2f}%", end="", flush=True)

            termination_marker = cipher_aes.encrypt(pad(b"END_OF_FILE", AES.block_size))
            client_socket.sendall(termination_marker)
            print(f"\nFile {filename} ({file_size} bytes) encrypted and sent successfully!")

    except FileNotFoundError:
        print(f"Error: File {filename} not found!")
    except Exception as e:
        print(f"Error: {e}")

def main():
    # Server details
    SERVER_IP = "127.0.0.1"
    PORT = 5001

    # Load the server's public key for RSA encryption
    server_public_key = get_public_key()
    rsa_cipher = PKCS1_OAEP.new(server_public_key)

    # Generate AES key and IV
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Encrypt AES key with RSA and send to server
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    print("AES key and IV encrypted and sent!")
    
    while True:
        filename = input("Enter filename to upload (or 'exit' to quit): ")
        if filename.lower() == "exit":
            break  # Stop the client loop

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_IP, PORT))
            client_socket.sendall(struct.pack("!I", len(enc_aes_key)) + enc_aes_key)  # Send AES key
            client_socket.sendall(iv)  # Send IV
            ## replace filename with USERNAME_AADHAR_TIMESTAMP or USERNAME_DL_TIMESTAMP etc
            upload_handler(client_socket, filename, aes_key, iv)

if __name__ == "__main__":
    main()
