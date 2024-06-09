from kademlia.network import Server
from kademlia.protocol import KademliaProtocol
import asyncio

local_storage = {}

class CustomProtocol(KademliaProtocol):
    async def call_store_and_propagate(self, node, key, value):
        await self.call_store(node, key, value)  # 会尝试连接node这个节点从而让它存储数据

    async def handle_store(self, sender, nodeid, key, value):
        print(f'发送请求来自 {sender}，其 key 为 {key}，value 为 {value}')
        if key not in local_storage:
            local_storage[key] = []  # 不存在则新建
        local_storage[key].append(value)
        return True

    async def handle_find_value(self, sender, nodeid, key):
        print(f"节点 {sender} 要请求的key是: {key}")
        if key in local_storage:
            return local_storage[key]
        else:
            return None

class CustomServer(Server):
    protocol_class = CustomProtocol

    def __init__(self):
        super().__init__()

    async def set_and_propagate(self, key, value, replication_factor=3, ttl=3):
        # 本地存储数据
        if key not in local_storage:
            local_storage[key] = []  # 不存在则新建
        local_storage[key].append(value)

        # 获取 k 个最近的节点
        key_hash = self.protocol.get_hash(key)
        closest_nodes = self.protocol.router.find_nodes(key_hash)

        # 确保只选择 replication_factor 个节点进行数据传播
        if len(closest_nodes) < replication_factor:
            replication_factor = len(closest_nodes)

        for i in range(replication_factor):
            try:
                await self.protocol.call_store_and_propagate(closest_nodes[i], key, value)
                print(f"Value propagated to node: {closest_nodes[i]} with ttl: {ttl-1}")
            except Exception as e:
                print(f"Error propagating value to node {closest_nodes[i]}: {e}")

    async def get_all_data(self):
        return local_storage  # 返回本地存储的数据

async def bootstrap_node(node: CustomServer, port, bootstrap_node=None):
    await node.listen(port, interface='0.0.0.0')
    if bootstrap_node:
        await node.bootstrap([bootstrap_node])
    print(f"Node listening on port {port}")

async def store_and_propagate_value(node: CustomServer, key, val):
    try:
        await node.set_and_propagate(key, val)
        print(f"Value stored and propagated: {key} -> {val}")
    except Exception as e:
        print(f"Error during set and propagate operation: {e}")

async def run():
    node = CustomServer()
    await bootstrap_node(node, 1316, bootstrap_node=("172.18.215.20", 1315))

    # 存储并传播数据
    await store_and_propagate_value(node, 'key1', 'value1')
    await store_and_propagate_value(node, 'key2', 'value2')

    # 等待数据传播
    await asyncio.sleep(5)

    # 获取所有本地存储的数据（用于调试）
    all_data = await node.get_all_data()
    print("All data in node:", all_data)

loop = asyncio.get_event_loop()
loop.run_until_complete(run())
