import socket
import time
import threading
def client(server_host, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((server_host, server_port))
        while True:
            print("Connected to server")
            message = input('输入你要发送的东西：')
            sock.sendall(message.encode())  # 发送消息