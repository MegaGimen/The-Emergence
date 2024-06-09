from kademlia.network import Server
import asyncio
async def run(port):
    server = Server()
    
    await server.listen(port,interface='0.0.0.0')
async def run_server(port):# 引导节点，全网的第一个节点这样子启动
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(port))
    loop.run_forever()
'''
---
'''
async def con(node:Server,listen_port,conlist:list):#连接其他的节点，可以是引导节点也可以不是
    await node.listen(listen_port)
    await node.bootstrap(conlist)# 元组列表

async def store_value(node:Server,key,val):
    try:
        await node.set(key, val)
        print("Value stored")
    except Exception as e:
        print(f"Error during set operation: {e}")

async def get_value(node:Server,key):
    try:
        result = await node.get(key)
        print("Retrieved value: ", result)
    except Exception as e:
        print(f"Error during get operation: {e}")