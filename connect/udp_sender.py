import socket

def send_udp_message(message, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip, port)
# 发送消息
    print(f"Sending message: {message}")
    sent = sock.sendto(message.encode(), server_address)
    sock.close()

# 示例使用
ip_address = '211.149.247.61'
#ip_address='192.168.1.22'
#ip_address='172.18.215.229'
#ip_address='127.0.0.1'
port_number = 59262
message_to_send = 'He'
import time
while True:
    send_udp_message(message_to_send, ip_address, port_number)
    time.sleep(1)