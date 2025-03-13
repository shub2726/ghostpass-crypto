### client.py ###
import socket
import time

def request_token(document_name):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5000))
    
    client_socket.send(f"REQUEST_TOKEN|{document_name}".encode())
    token = client_socket.recv(1024).decode()
    print(f"[CLIENT] Received token: {token}")
    client_socket.close()
    return token

def send_token_to_third_party(token):
    time.sleep(11)  # Simulate delay before sending token to third party
    third_party_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    third_party_socket.connect(("localhost", 6000))
    
    third_party_socket.send(token.encode())
    print("[CLIENT] Sent token to third party")
    third_party_socket.close()

def client():
    document_name = "sample_document.pdf"
    token = request_token(document_name)
    send_token_to_third_party(token)

if __name__ == "__main__":
    time.sleep(1)  # Ensure server is running before client starts
    client()