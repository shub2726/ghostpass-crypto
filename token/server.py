### server.py ###
import socket
import threading
import random
import string
import time

# Dictionary to store document tokens with timestamps
document_tokens = {}

def generate_dummy_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def handle_client(conn, addr):
    global document_tokens
    print(f"[SERVER] Connection from {addr}")
    
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        
        request = data.split('|')
        if request[0] == "REQUEST_TOKEN":
            document_name = request[1]
            token = generate_dummy_token()
            document_tokens[token] = time.time()  # Store token with timestamp
            conn.send(token.encode())
        
        elif request[0] == "VERIFY_TOKEN":
            token = request[1]
            if token in document_tokens:
                elapsed_time = time.time() - document_tokens[token]
                if elapsed_time <= 10:  # Token expires after 10 seconds
                    conn.send("VALID".encode())
                else:
                    conn.send("EXPIRED".encode())
                    del document_tokens[token]
            else:
                conn.send("INVALID".encode())
    
    conn.close()

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5000))
    server_socket.listen(5)
    print("[SERVER] Running on port 5000")
    
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    server()