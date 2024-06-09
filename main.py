import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import asyncio
import os
import asyncio
from kademlia.protocol import KademliaProtocol
import itertools
from kademlia.utils import digest
from kademlia.storage import ForgetfulStorage
from kademlia.node import Node
from kademlia.crawling import ValueSpiderCrawl
from kademlia.crawling import NodeSpiderCrawl
from kademlia.network import Server
from kademlia.protocol import KademliaProtocol
from kademlia.node import Node
from connect.nwct import *
import binascii
import traceback
import copy
import tkinter as tk
import threading
from tkinter import PhotoImage
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
import json
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import asyncio
import pickle

local_storage = {}
keylist = []
knownhost = []
def get_knownhost():
    url = "http://211.149.247.61:1314/get_all_hosts"
    response=requests.get(url)
    result=response.json()
    ret=[]
    for _ in result:
        ret.append(tuple(_))
    return ret
def get_hash(key):
    return hashlib.sha1(key.encode()).hexdigest()
def update_local_storage_file():
    #用于在任何地方保存localstorage到本地
    tmp_local_storage={key.hex(): value for key, value in local_storage.items()}
    json_str = json.dumps(tmp_local_storage)
    with open('./local_storage.json', 'w') as json_file:
        json_file.write(json_str)
    with open('./keypairs.pkl', 'wb') as file:
        pickle.dump(keylist, file)
def load_local_storage():
    global local_storage
    global keylist
    path='./local_storage.json'
    path_key='./keypairs.pkl'
    try:
        with open(path, 'r') as json_file:
            json_str = json_file.read()
            hexstr_local_storage=json.loads(json_str)
            local_storage={bytes.fromhex(key): value for key, value in hexstr_local_storage.items()}
    except Exception as e:
        print('此时还没有本地存储关系数据呢')
    try:
        with open(path_key, 'rb') as file:
            keylist = pickle.load(file)
    except Exception as e:
        print('no k, boys!')
        #pass#
class CustomProtocol(KademliaProtocol):
    def rpc_store(self, sender, nodeid, key, value,ip,port):
        source = Node(nodeid, ip, port)
        self.welcome_if_new(source)
        print(f'有人让你保存个东西：key={key},value={value}')
        #log.debug("got a store request from %s, storing '%s'='%s'",
        #          sender, key.hex(), value)
        #self.storage[key] = value
        if key not in local_storage:
            local_storage[key] = []
        local_storage[key].append(value)
        update_local_storage_file()
        return True
    def rpc_find_value(self, sender, nodeid, key,ip,port):
        source = Node(nodeid,ip, port)
        self.welcome_if_new(source)
        try:
            value = local_storage[key]
        except Exception as e:
            print('你这东西我这里可没有，我给你去问问其他人哈')
            return self.rpc_find_node(sender, nodeid, key,ip,port)
        return {'value': value}


class CustomServer(Server):
    protocol_class = CustomProtocol

    def __init__(self):
        super().__init__()
        self.protocol = KademliaProtocol(self.node, self.storage, ksize=self.ksize)

    async def set_and_propagate(self, key, value, replication_factor=3, ttl=3):
        key_hash = get_hash(key)
        key_hash = bytes.fromhex(key_hash)
        if key_hash not in local_storage:
            local_storage[key_hash] = []
        local_storage[key_hash].append(value)
        update_local_storage_file()
        closest_nodes = self.protocol.router.find_neighbors(Node(key_hash))

        if len(closest_nodes) < replication_factor:
            replication_factor = len(closest_nodes)

        for i in range(replication_factor):
            try:
                global fport
                ip,port='211.149.247.61',fport
                await self.protocol.call_store(closest_nodes[i], key_hash, value,ip,port)
                print(f"Value propagated to node: {closest_nodes[i]} with ttl: {ttl-1}")
            except Exception as e:
                print(f"Error propagating value to node {closest_nodes[i]}: {e}")
    async def bootstrap_node(self, addr,datas):
        ip,port=datas.split(':')[0],datas.split(':')[1]
        result = await self.protocol.ping(addr, (self.node.id,ip,port))
        return Node(result[1], addr[0], addr[1]) if result[0] else None
    async def bootstrap(self, addrs,datas):
        print(f'bootstrap args!{addrs},{datas}')
        ip,port=datas
        ip=ip[0]
        port=port[0]
        """
        Bootstrap the server by connecting to other known nodes in the network.

        Args:
            addrs: A `list` of (ip, port) `tuple` pairs.  Note that only IP
                   addresses are acceptable - hostnames will cause an error.
        """
        datas=ip+':'+str(port)
        cos = list(map(self.bootstrap_node, addrs,[datas]))
        gathered = await asyncio.gather(*cos)
        nodes = [node for node in gathered if node is not None]
        spider = NodeSpiderCrawl(self.protocol, self.node, nodes,
                                 self.ksize, self.alpha)
        return await spider.find(datas)
    async def get_all_data(self):
        return local_storage

    async def find_val(self, key):
        key_hash = get_hash(key)
        key_hash = bytes.fromhex(key_hash)
        closest_nodes = self.protocol.router.find_neighbors(Node(key_hash))
        print(f'一些比较近的节点：{closest_nodes}')
        print(f"我正在在DHT中查找键 {key} 对应的值，最接近的节点: {[node.id for node in closest_nodes]}，正在查询！")
        ret = set()
        for node in closest_nodes:
            try:
                global fport
                response = await self.protocol.call_find_value(node, Node(key_hash),'211.149.247.61',fport)
                print(f'debugresponse:{response}')
                response=response[1]['value']
                #需要把response这个嵌套列表转换为元组列表
                response=[tuple(inner_list) for inner_list in response]
                if response is not None:
                    print(f"从节点 {node.id} 找到值: {response}")
                    ret = ret | set(response)  # 取所有东西的并集
            except Exception as e:
                print(f"Error finding value from node {node}: {e}")
        if len(ret) == 0:
            return None
            raise ValueError('可恶，你找的键在DHT中找不到阿')
        else:
            return ret

async def store_and_propagate_value(node: CustomServer, key, val):
    await node.set_and_propagate(key, val)
    print(f"Value stored and propagated: {key} -> {val}")

async def run(node:CustomServer, port, is_root_server=True, ip_list=None):
    print(f'iplist in run:{ip_list}')
    if not is_root_server and ip_list is None:
        raise RuntimeError('Non-root node requires IP list.')
    try:
        print('ready to listen')
        await node.listen(port, interface='0.0.0.0')
    except Exception as e:
        print(f'发现你了：{e}')
    global fip
    global fport
    if is_root_server:
        while True:
            print(f'引导节点还在坚持着，它还能坚持多久呢？')
            #url='http://211.149.247.61:1314/update_a_host'
            #data = {
            #"ip": fip,
            #"port": int(fport)
            #}
            #response = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(data))
            #if response.status_code==200:
            #    print('发送成功')
            #else:
            #    raise RuntimeError('发送失败')
            await asyncio.sleep(3600)
    else:
        try:
            test=await node.bootstrap(ip_list,(['211.149.247.61'],[fport]))
            #test=None
            print(f'bootstrap debug:{test}')
            #url='http://211.149.247.61:1314/update_a_host'
            #data = {
            #"ip": fip,
            #"port": int(fport)
            #}
            #response = requests.post(url, headers={"Content-Type": "application/json"}, data=json.dumps(data))
            #if response.status_code==200:
            #    print('发送成功')
            #else:
            #    raise RuntimeError('发送失败')
        except Exception as e:
            print(f'似乎出现了一些异常啊啊啊啊：{e}')
            traceback.print_exc()
        while True:
            print('普通节点开启!')
            node.protocol.router.print_bucket()
            print(f'值得注意的是，当前节点的id为：{node.node.id}')
            print('我不会告诉你，我偷偷地把一个不存在的ip加进去了！它的port是38402')
            tmpkeyhash=get_hash('Kobe Bryant')
            tmpkeyhash=bytes.fromhex(tmpkeyhash)
            node.protocol.router.add_contact(Node(tmpkeyhash,'211.149.247.61',38402))
            await asyncio.sleep(3600)
    return node

def gen_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    sk = private_pem.hex()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pk = public_pem.hex()
    return sk, pk

def encrypt_msg(msg: str, pk):
    pem_public_key = binascii.unhexlify(pk)
    public_key = serialization.load_pem_public_key(pem_public_key, backend=default_backend())
    encrypted = public_key.encrypt(
        msg.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None  # 正确放置 label 参数
        )
    )
    return encrypted.hex()
def decrypt_msg(encrypted_msg: str, sk):
    # 将16进制字符串私钥转换回PEM格式
    pem_private_key = binascii.unhexlify(sk)
    private_key = serialization.load_pem_private_key(pem_private_key, password=None, backend=default_backend())

    # 解密消息
    decrypted = private_key.decrypt(
        binascii.unhexlify(encrypted_msg),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()
async def establish_relationship(node: CustomServer, me, tar,is_private,is_root_server=False):
    key = me
    val = tar
    if is_private:
        sk, pk = gen_key_pair()
        keylist.append((sk, pk))
        print(f'debug_is_private,val={val}')
        tmpval=list(val)
        tmpval[0] = encrypt_msg(val[0], pk=pk)
        tmpval[1] = encrypt_msg(val[1], pk=pk)
        val=tmpval
    if not is_root_server:
        try:
            print(f'debug_val_tup:{val}')
            await store_and_propagate_value(node, key, val)
        except Exception as e:
            print(f'出错了3，错误是：{e}')
            print('具体地：')
            traceback.print_exc()
            print('-'*50)
    else:
        key_hash = get_hash(key)
        key_hash = bytes.fromhex(key_hash)
        if key_hash not in local_storage:
            local_storage[key_hash] = []
        local_storage[key_hash].append(val)
        update_local_storage_file()
def try_unlock_with_keylist(val:tuple,keylist:list):#这里的val也是一个元组
    for sk,pk in keylist:
        #使用私钥尝试解密
        try:
            name=decrypt_msg(val[0],sk)
            how=decrypt_msg(val[1],sk)
            return True,(name,how)
        except Exception as e:
            pass
    return False,None#每一个能用的！
async def query_who_know_him(node:CustomServer, key):# 单点查询：谁认识ta？
    find_key = key
    print(f'debug,find_key={find_key}')
    result = await node.find_val(find_key)
    print(f'debug,result={result}')
    if result==None:
        return None
    decry_result=set()
    for friend in result:#friend应该是一个个元组，元组的第一个是姓名，第二个是如何认识的
        if len(friend[0])<10:#没被加密
            decry_result.add(friend)
        else:
            tryd=try_unlock_with_keylist(friend,keylist)
            if tryd[0]!=False:
                decry_result.add(tryd[1])
    print(f"查找到的结果: {decry_result}")
    #值得追问的是，查询到的结果是否被加密了，如果被加密了，即文字长度>30，那么就会尝试使用自己的keylist进行解密，如果无法解密，那么就跳过它
    return decry_result
'''
期望的返回结果格式：一个集合，集合的每一个元素都是一个元组，元组的第一个元素是人名，第二个是“如何认识的”，比如小学同学、SAT同学
'''
async def query_link(node:CustomServer,a,b):#查询a到b节点的关系路径,如果没有则会返回(False,None)，反之则是(True,[关系列表])
    q=[]
    q1=[]#用于存储连续的路径信息，其内容也是元组，但第二个元素是多个关系，这相当于是BFS的“如何搜索到的，即路径搜索”
    #BFS
    q.append((a,None))
    q1.append((a,[]))
    flag={}
    flag[a]=True
    while len(q)!=0:
        top=q[0]
        top1=q1[0]
        del q[0]
        del q1[0]
        if top[0]==b:
            return True,top1[1]
        whoknow=await query_who_know_him(node,key=top[0])
        print(f'debug,whoknow={whoknow}')
        if whoknow==None:
            continue
        for connection in iter(whoknow):#遍历集合
            baserelation=copy.deepcopy(top1[1])
            if (connection in flag.keys()):
                if flag[connection]==True:#已经遍历过了，防止死循环
                    continue
            q.append(connection)
            baserelation.append(connection[1])
            q1.append((connection[0],copy.deepcopy(baserelation)))
            flag[connection]=True
    return False,None

def create(node:CustomServer,who, with_whom, encryption, how_met):
    is_enc=False
    if encryption=='加密':
        is_enc=True
    asyncio.run(establish_relationship(node,me=who,tar=(with_whom,how_met),is_private=is_enc,is_root_server=False))
    print(f"新建: 谁: {who}, 和谁: {with_whom}, 加密: {encryption}, 如何认识的: {how_met}")
def query(node:CustomServer,who, with_whom):
   # messagebox.showinfo("查询", f"查询: 谁: {who}, 和谁: {with_whom}")
    print(f"查询: 谁: {who}, 和谁: {with_whom}")
    stat,result=asyncio.run(query_link(node,who,with_whom))
    if stat==False:
        print('没找着')
        #messagebox.showerror(f'很抱歉，没有找到信息')
    else:
        print(f'这个关系链是：{result}')
        #messagebox.showinfo(f'这个关系链是：{result}')

class MyGUI:
    def __init__(self, node, root, image_path='yx.png'):
        self.cnt = 0
        self.node = node
        self.root = root
        self.root.title("主窗口")
        self.root.geometry("1920x1080")  # 初始大小
        self.root.state('zoomed')  # 窗口最大化启动
        self.root.configure(bg='#000A3F')  # 设置背景颜色

        # 图片和标签
        self.image_path = image_path
        self.image_label = tk.Label(self.root, bg='#000A3F')
        self.image_label.pack(padx=10, pady=10)

        # 显示缓慢闪烁的文字
        self.flash_label = tk.Label(self.root, text="\"Emerge spontaneously, Illuminare, and Enlightenment\"", font=("Helvetica", 16), fg="white", bg="#000A3F")
        self.flash_label.pack(pady=20)
        self.alpha_gen = itertools.cycle(list(range(0, 100, 5)) + list(range(100, 0, -5)))  # 生成透明度变化序列
        self.root.after(50, self.breathe_text)

        # 按钮框架
        self.button_frame = tk.Frame(self.root, bg='#000A3F')
        self.button_frame.pack(pady=10, fill=tk.X, expand=True)

        self.query_button = tk.Button(self.button_frame, text="查询", command=self.open_query_window, height=3, font=('Microsoft YaHei', 14))
        self.query_button.pack(pady=10, fill=tk.X, expand=True)

        self.create_button = tk.Button(self.button_frame, text="新建", command=self.open_create_window, height=3, font=('Microsoft YaHei', 14))
        self.create_button.pack(pady=10, fill=tk.X, expand=True)

        self.exit_button = tk.Button(self.button_frame, text="退出", command=self.quit, height=3, font=('Microsoft YaHei', 14))
        self.exit_button.pack(pady=10, fill=tk.X, expand=True)

        # 绑定窗口大小变化事件
        self.root.bind("<Configure>", self.on_resize)
        self.update_image_size()
    def quit(self):
        os._exit(0)
    def breathe_text(self):
        alpha = next(self.alpha_gen) / 100
        color_value = int(255 * alpha)
        color = f'#{color_value:02x}{color_value:02x}{color_value:02x}'
        self.flash_label.config(fg=color)  # 调整前景色的亮度
        self.root.after(50, self.breathe_text)

    def resize_image(self, image_path, max_width, max_height):
        image = Image.open(image_path)
        width_ratio = max_width / image.width
        height_ratio = max_height / image.height
        scale_ratio = min(width_ratio, height_ratio)
        new_size = (int(image.width * scale_ratio), int(image.height * scale_ratio))
        if new_size[0] > 0 and new_size[1] > 0:  # 检查新尺寸的有效性
            image = image.resize(new_size, Image.LANCZOS)
        return ImageTk.PhotoImage(image)

    def update_image_size(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        newpadx = (width - 567) / 2
        if newpadx > 0:
            self.image_label.pack_configure(padx=0)

        if width > 0 and height > 0:
            new_image = self.resize_image(self.image_path, width, height // 3)
            self.image_label.config(image=new_image)
            self.image_label.image = new_image  # 保持对图像的引用，防止被垃圾回收

    def on_resize(self, event):
        self.cnt += 1
        self.update_image_size()

    def handle_query(self, who, with_whom):
        thread_query = threading.Thread(target=query, args=(self.node, who, with_whom,))
        thread_query.start()

    def handle_create(self, who, with_whom, encryption, how_met):
        thread_create = threading.Thread(target=create, args=(self.node, who, with_whom, encryption, how_met,))
        thread_create.start()

    def open_query_window(self):
        self.clear_window()

        self.create_labeled_entry("谁？", "who_entry", font_size=18)
        self.create_labeled_entry("和谁？", "with_whom_entry", font_size=18)

        def on_query():
            who = self.who_entry.get()
            with_whom = self.with_whom_entry.get()
            if not who or not with_whom:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                self.handle_query(who, with_whom)

        self.button_query_sub = tk.Button(self.root, text="查询", command=on_query, font=("Microsoft YaHei", 18))
        self.button_query_sub.pack(pady=10, fill=tk.X)

        tk.Button(self.root, text="返回", command=self.show_main_window, font=("Microsoft YaHei", 18)).pack(pady=10)
        tk.Button(self.root, text="退出", command=self.quit, font=("Microsoft YaHei", 18)).pack(pady=10)

    def open_create_window(self):
        self.clear_window()

        self.create_labeled_entry("谁？", "who_entry", font_size=18)
        self.create_labeled_entry("和谁？", "with_whom_entry", font_size=18)
        self.create_labeled_entry("如何认识的", "how_met_entry", font_size=18)

        tk.Label(self.root, text="选择加密方式", bg='#000A3F', fg='white', font=("Microsoft YaHei", 18)).pack(pady=5)

        # Use normal buttons for encryption selection
        self.encryption_choice = None
        frame = tk.Frame(self.root, bg='#000A3F')
        frame.pack(pady=5)

        self.encrypt_button = tk.Button(frame, text="加密", font=("Microsoft YaHei", 18), command=lambda: self.select_encryption("加密"))
        self.encrypt_button.pack(side=tk.LEFT, padx=10)
        self.no_encrypt_button = tk.Button(frame, text="不加密", font=("Microsoft YaHei", 18), command=lambda: self.select_encryption("不加密"))
        self.no_encrypt_button.pack(side=tk.LEFT, padx=10)

        def on_create():
            who = self.who_entry.get()
            with_whom = self.with_whom_entry.get()
            how_met = self.how_met_entry.get()
            if not who or not with_whom or not how_met or self.encryption_choice is None:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                self.handle_create(who, with_whom, self.encryption_choice, how_met)

        self.button_create_sub = tk.Button(self.root, text="确定", command=on_create, font=("Microsoft YaHei", 18))
        self.button_create_sub.pack(pady=10, fill=tk.X)

        tk.Button(self.root, text="返回", command=self.show_main_window, font=("Microsoft YaHei", 18)).pack(pady=10)
        tk.Button(self.root, text="退出", command=self.quit, font=("Microsoft YaHei", 18)).pack(pady=10)

    def select_encryption(self, choice):
        self.encryption_choice = choice
        if choice == "加密":
            self.encrypt_button.configure(bg="darkblue", fg="white")
            self.no_encrypt_button.configure(bg="lightgrey", fg="black")
        else:
            self.encrypt_button.configure(bg="lightgrey", fg="black")
            self.no_encrypt_button.configure(bg="darkblue", fg="white")

    def create_labeled_entry(self, label_text, entry_var_name, font_size):
        frame = tk.Frame(self.root, bg='#000A3F')
        frame.pack(pady=5, fill=tk.X)

        label = tk.Label(frame, text=label_text, bg='#000A3F', fg='white', font=("Microsoft YaHei", font_size))
        label.pack(side=tk.LEFT, padx=10)

        entry = tk.Entry(frame, font=("Microsoft YaHei", font_size))
        entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=10)

        setattr(self, entry_var_name, entry)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.pack_forget()

    def show_main_window(self):
        self.clear_window()
        self.image_label.pack(padx=10, pady=10)
        self.flash_label.pack(pady=20)
        self.button_frame.pack(pady=10, fill=tk.X, expand=True)
        self.query_button.pack(pady=10, fill=tk.X, expand=True)
        self.create_button.pack(pady=10, fill=tk.X, expand=True)
        self.exit_button.pack(pady=10, fill=tk.X, expand=True)
        self.update_image_size()
def run_server(node:CustomServer,port,is_root=True,iplist=None):
    asyncio.run(run(node,port,is_root,iplist))
async def create_and_run_gui():
    load_local_storage()
    global knownhost
    knownhost=[('211.149.247.61',59262)]
    #print(f'debug:{knownhost}')
    key='secretkey' 
    val='secretval1'
    key_hash = get_hash(key)
    key_hash = bytes.fromhex(key_hash)
    local_storage[key_hash]=[]
    local_storage[key_hash].append(val)

    port = 8469
    forwarded_ip=await forward_but_not_AI(port)
    print(f'NOIP:{forwarded_ip}')
    global fip
    global fport
    fip,fport=forwarded_ip.split(':')[0],int(forwarded_ip.split(':')[1])
    node = CustomServer()
    thread=threading.Thread(target=run_server,args=(node,port,False,knownhost,))
    thread.start()
    root = tk.Tk()
    app = MyGUI(node,root)
    while True:
        root.update()
        time.sleep(0.01)
    # 将 asyncio 事件循环嵌入到 Tkinter 事件循环中
    async def main_loop():
        while True:
            try:
                root.update()
                await asyncio.sleep(0.01)
            except tk.TclError as e:
                if "application has been destroyed" not in str(e):
                    raise
                break

    asyncio.run(main_loop())
async def main():
    await create_and_run_gui()
loop = asyncio.get_event_loop()
loop.run_until_complete(main())