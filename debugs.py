import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import asyncio
import asyncio
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
    def rpc_store(self, sender, nodeid, key, value):
        source = Node(nodeid, sender[0], sender[1])
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
    def rpc_find_value(self, sender, nodeid, key):
        source = Node(nodeid, sender[0], sender[1])
        self.welcome_if_new(source)
        try:
            value = local_storage[key]
        except Exception as e:
            print('你这东西我这里可没有，我给你去问问其他人哈')
            return self.rpc_find_node(sender, nodeid, key)
        return {'value': value}
    async def call_store_and_propagate(self, node, key, value):
        try:
            await self.call_store(node, key, value)
        except Exception as e:
            print(f'出错了1，错误是：{e}')

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
                await self.protocol.call_store_and_propagate(closest_nodes[i], key_hash, value)
                print(f"Value propagated to node: {closest_nodes[i]} with ttl: {ttl-1}")
            except Exception as e:
                print(f"Error propagating value to node {closest_nodes[i]}: {e}")

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

                response = await self.protocol.call_find_value(node, Node(key_hash))
                print(f'debugresponse:{response}')
                response=response[1]['value']
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
    if not is_root_server and ip_list is None:
        raise RuntimeError('Non-root node requires IP list.')
    try:
        await node.listen(port, interface='0.0.0.0')
    except Exception as e:
        print(f'发现你了：{e}')
    if is_root_server:
        while True:
            print(f'引导节点还在坚持着，它还能坚持多久呢？')
            await asyncio.sleep(3600)
    else:
        try:
            test=await node.bootstrap(ip_list)
            print(f'bootstrap debug:{test}')
        except Exception as e:
            print(f'似乎出现了一些异常啊啊啊啊：{e}')
            traceback.print_exception()
        while True:
            print('普通节点开启!')
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
        val = encrypt_msg(val, pk=pk)
    if not is_root_server:
        try:
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
def try_unlock_with_keylist(val:tuple,keylist:list):
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
    result = await node.find_val(find_key)
    print(f'debug,result={result}')
    if result==None:
        return None
    decry_result=set()
    for friend in result:
        if len(friend)<10:#没被加密
            decry_result.add(friend)
        tryd=try_unlock_with_keylist(friend,keylist)
        if tryd[0]!=False:
            decry_result.add(tryd)
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
    def __init__(self,node:CustomServer, root, image_path='yx.png'):
        self.node=node

        self.root = root
        self.root.title("主窗口s")
        self.root.geometry("400x400")

        # 加载并调整图片大小
        self.image_path = image_path
        self.image = self.resize_image(image_path, 200, 200)

        image_label = tk.Label(self.root, image=self.image)
        image_label.pack(pady=20)

        # 放置按钮
        query_button = tk.Button(self.root, text="查询", command=self.open_query_window)
        query_button.pack(pady=10)

        create_button = tk.Button(self.root, text="新建", command=self.open_create_window)
        create_button.pack(pady=10)

    def resize_image(self, image_path, width, height):
        image = Image.open(image_path)
        image = image.resize((width, height), Image.LANCZOS)
        return ImageTk.PhotoImage(image)

    def handle_query(self, who, with_whom):
        thread_query=threading.Thread(target=query,args=(self.node,who,with_whom,))
        thread_query.start()

    def handle_create(self, who, with_whom, encryption, how_met):
        thread_create=threading.Thread(target=create,args=(self.node,who,with_whom,encryption,how_met,))
        thread_create.start()

    def open_query_window(self):
        query_window = tk.Toplevel(self.root)
        query_window.title("查询")
        query_window.geometry("300x200")

        tk.Label(query_window, text="谁？").pack(pady=5)
        who_entry = tk.Entry(query_window)
        who_entry.pack(pady=5)

        tk.Label(query_window, text="和谁？").pack(pady=5)
        with_whom_entry = tk.Entry(query_window)
        with_whom_entry.pack(pady=5)

        def on_query():
            who = who_entry.get()
            with_whom = with_whom_entry.get()
            if not who or not with_whom:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                #asyncio.create_task(self.handle_query(who, with_whom))
                self.handle_query(who, with_whom)
                #self.handle_query(who, with_whom)

        tk.Button(query_window, text="查询", command=on_query).pack(pady=10)

    def open_create_window(self):
        create_window = tk.Toplevel(self.root)
        create_window.title("新建")
        create_window.geometry("300x300")

        # 配置列权重，使内容居中
        create_window.columnconfigure(0, weight=1)
        create_window.columnconfigure(1, weight=1)

        tk.Label(create_window, text="谁？").grid(row=0, column=0, padx=10, pady=5, sticky='e')
        who_entry = tk.Entry(create_window)
        who_entry.grid(row=0, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="和谁？").grid(row=1, column=0, padx=10, pady=5, sticky='e')
        with_whom_entry = tk.Entry(create_window)
        with_whom_entry.grid(row=1, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="如何认识的").grid(row=2, column=0, padx=10, pady=5, sticky='e')
        how_met_entry = tk.Entry(create_window)
        how_met_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="选择加密方式").grid(row=3, column=0, columnspan=2, pady=5)
        encryption = tk.StringVar(value="加密")
        tk.Radiobutton(create_window, text="加密", variable=encryption, value="加密").grid(row=4, column=0, padx=10, pady=5)
        tk.Radiobutton(create_window, text="不加密", variable=encryption, value="不加密").grid(row=4, column=1, padx=10, pady=5)

        def on_create():
            who = who_entry.get()
            with_whom = with_whom_entry.get()
            how_met = how_met_entry.get()
            encryption_choice = encryption.get()
            if not who or not with_whom or not how_met:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                #asyncio.create_task(self.handle_create(who, with_whom, encryption_choice, how_met))
                self.handle_create(who, with_whom, encryption_choice, how_met)

        tk.Button(create_window, text="确定", command=on_create).grid(row=5, column=0, columnspan=2, pady=10)


def run_server(node:CustomServer,port,is_root=True,iplist=None):
    asyncio.run(run(node,port,is_root,iplist))
async def create_and_run_gui():
    load_local_storage()
    global knownhost
    knownhost=[]
    print(f'debug:{knownhost}')
    key='secretkey'
    val='secretval1'
    key_hash = get_hash(key)
    key_hash = bytes.fromhex(key_hash)
    local_storage[key_hash]=[]
    local_storage[key_hash].append(val)

    port = 1145
    node = CustomServer()
    thread=threading.Thread(target=run_server,args=(node,port,))
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