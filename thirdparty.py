import socket
import json

def verify_token_with_server(server_ip, server_port, token, docs):
    """Forwards the token to the server for verification."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        request = {"action": "verify_token", "token": token, "docs": docs}
        client_socket.send(json.dumps(request).encode())
        response = json.loads(client_socket.recv(4096).decode())
        print(f"[THIRD-PARTY] {response}")
        return response
    finally:
        client_socket.close()

def handle_third_party_request(client_socket):
    """Handles a token verification request from the client."""
    request = json.loads(client_socket.recv(4096).decode())
    if request["action"] == "ask_needed_docs":
        # Forward the docs needed to the client for verification
        docs = ["aadhar", "DL"]
        response = docs
        print(f"[THIRD-PARTY] Asking for {docs}")
        # Send the verification response back to the client
        client_socket.send(json.dumps(response).encode())

        server_ip = "127.0.0.1"
        server_port = 12345
        token = input("Enter your Token: ")
        response = verify_token_with_server(server_ip, server_port, token, docs)

        # Send the verification response back to the client
        client_socket.send(json.dumps(response).encode())

def start_third_party_server(host="127.0.0.1", port=6000):
    """Starts the third-party verification server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[THIRD-PARTY] Listening on {host}:{port}...")

    while True:
        client_socket, _ = server.accept()
        handle_third_party_request(client_socket)
        client_socket.close()

# Start the third-party server
start_third_party_server()
