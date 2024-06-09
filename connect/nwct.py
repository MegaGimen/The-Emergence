import os
import time
import asyncio
import subprocess
import requests
import uuid
async def forward_but_not_AI(port):
    url = 'http://211.149.247.61:3070/get_free_port'
    response=requests.get(url=url)
    server_port=int(response.text)
    #server_port=43678
    id=str(uuid.uuid4())
    #server_port=43678
    print(f'debug:{server_port}')
    configure_text=f'''
[common]
server_addr = 211.149.247.61
server_port = 7000

[{id}]
type = udp
local_ip = 127.0.0.1
local_port = {port}
remote_port = {server_port}
'''
    
    
    configure_text=f'''
[common]
server_addr = 211.149.247.61
server_port = 7000

[debug]
type = udp
local_ip = 127.0.0.1
local_port = {port}
remote_port = {server_port}
'''
    try:
        os.remove('frp_0.58.0_windows_amd64/frpc.ini')
    except FileNotFoundError:
        pass
    with open('frp_0.58.0_windows_amd64/frpc.ini','w')as f:
        f.write(configure_text)
    #写入配置文件frpc.ini
    path='frp_0.58.0_windows_amd64/frpc.exe'
    ini_path='frp_0.58.0_windows_amd64/frpc.ini'
    cmd = f'Start-Process -FilePath "{path}" -ArgumentList "-c {ini_path} " -RedirectStandardOutput "nwct.log" -RedirectStandardError "err.log" -NoNewWindow'
    print(cmd)
    process = subprocess.run(["powershell", "-Command", cmd], capture_output=False, text=True)

    # 等待4秒钟连接
    print('正在连接，请等待4秒钟...')
    time.sleep(4)
    ip=f'211.149.247.61:{server_port}'
    return ip
async def backward_but_not_AI():#负责结束进程
    os.system("taskkill /IM frpc.exe /F")