### thirdparty.py ###
import socket
import threading

def handle_third_party(conn, addr):
    print(f"[THIRD-PARTY] Connection from {addr}")
    token = conn.recv(1024).decode()
    print(f"[THIRD-PARTY] Received token: {token}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(("localhost", 5000))
    server_socket.send(f"VERIFY_TOKEN|{token}".encode())
    validation = server_socket.recv(1024).decode()
    server_socket.close()
    
    print(f"[THIRD-PARTY] Token validation result: {validation}")
    conn.close()

def third_party():
    third_party_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    third_party_socket.bind(("localhost", 6000))
    third_party_socket.listen(5)
    print("[THIRD-PARTY] Running on port 6000")
    
    while True:
        conn, addr = third_party_socket.accept()
        threading.Thread(target=handle_third_party, args=(conn, addr)).start()

if __name__ == "__main__":
    third_party()
