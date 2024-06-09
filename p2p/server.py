import socket
import threading
def send_back(conn):
    resp=input('输入你要发送的信息：')
    conn.sendall(resp.encode())  # 发回接收到的数据
def handle_client(conn, addr):
    print(f"Connected by {addr}")
    while True:
        data = conn.recv(1024)  # 接收数据
        if not data:
            break
        print(f"Received from {addr}: {data.decode()}")
        thread1=threading.Thread(target=send_back,args=(conn,))
        thread1.start()
    conn.close()

def server():
    host = '127.0.0.1'
    port = 11451
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print("Server listening on port", port)
    while True:
        conn, addr = server_socket.accept()#blocking
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

# 可以在一个线程或进程中运行server函数
threading.Thread(target=server).start()
