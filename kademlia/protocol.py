import random
import asyncio
import logging

from rpcudp.protocol import RPCProtocol

from kademlia.node import Node
from kademlia.routing import RoutingTable
from kademlia.utils import digest

log = logging.getLogger(__name__)  # pylint: disable=invalid-name

async def clean_result(result,myip,myport):# Used to clean the unavailable nodes that return from bootstraping
    if not result[0]:
        return False,None
    nodelist=result[1]
    ret=[]
    for node in nodelist:
        nodeid=node[0]
        nodeip=node[1]
        nodeport=node[2]
        if (nodeip!=myip) and (nodeport!=myport):
            ret.append(node)
    return True,ret
class KademliaProtocol(RPCProtocol):
    def __init__(self, source_node, storage, ksize):
        RPCProtocol.__init__(self)
        self.router = RoutingTable(self, ksize, source_node)
        self.storage = storage
        self.source_node = source_node

    def get_refresh_ids(self):
        """
        Get ids to search for to keep old buckets up to date.
        """
        ids = []
        for bucket in self.router.lonely_buckets():
            rid = random.randint(*bucket.range).to_bytes(20, byteorder='big')
            ids.append(rid)
        return ids

    def rpc_stun(self, sender):  # pylint: disable=no-self-use
        return sender

    def rpc_store(self, sender, nodeid, key, value,ip,port):
        source = Node(nodeid, ip, port)
        print(f'rpc_store is called, source={source}')
        self.welcome_if_new(source)
        log.debug("got a store request from %s, storing '%s'='%s'",
                  sender, key.hex(), value)
        self.storage[key] = value
        return True
    def rpc_ping(self, sender, datas):
        print(f'debug,datanodeid={datas},sender={sender}')
        nodeid=datas[0]
        ip=datas[1]
        port=datas[2]
        source = Node(nodeid, ip, port)
        print(f'debug,ip={ip},port={port}')
        self.router.print_bucket()
        self.welcome_if_new(source)
        return self.source_node.id

    def rpc_find_node(self, sender, nodeid, key,ip,port):
        log.info("finding neighbors of %i in local table",
                 int(nodeid.hex(), 16))
        source = Node(nodeid, ip, port)
        print(f'rpc_find_node is called, source={source}')
        self.welcome_if_new(source)
        node = Node(key)
        neighbors = self.router.find_neighbors(node, exclude=source)
        print(list(map(tuple, neighbors)))
        return list(map(tuple, neighbors))
    async def call_find_node(self, node_to_ask, node_to_find,moreinfo):
        print(f'tmpdebug{node_to_find},nodetoasl={node_to_ask},moreinfo={moreinfo}')
        ip,port=moreinfo.split(':')[0],int(moreinfo.split(':')[1])
        address = (node_to_ask.ip, node_to_ask.port)
        print(f'tmpdebug,self.source_node.id={self.source_node.id},node_to_find.id={node_to_find.id}')
        result = await self.find_node(address, self.source_node.id,
                                      node_to_find.id,ip,port)
        print(f'debug,the result of call_find_node={result}')
        result= await clean_result(result,ip,port)
        print(f'debug,after cleaning:{result}')
        return self.handle_call_response(result, node_to_ask)

    async def call_find_value(self, node_to_ask, node_to_find,ip,port):
        address = (node_to_ask.ip, node_to_ask.port)
        print(f'call_find_value, args:address={address},self.source_node.id={self.source_node.id},node_to_find.id={node_to_find.id},ip={ip},port={port}')
        result = await self.find_value(address, self.source_node.id,
                                       node_to_find.id,ip,port)
        print(f'wow! I have done a lot of things! Maybe you need this!{result}')
        return self.handle_call_response(result, node_to_ask)

    async def call_ping(self, node_to_ask,ip,port):
        address = (node_to_ask.ip, node_to_ask.port)
        print(f'我正在ping别人，address是：{address}')
        result = await self.ping(address, self.source_node.id,ip,port)
        return self.handle_call_response(result, node_to_ask)

    async def call_store(self, node_to_ask, key, value,ip,port):
        address = (node_to_ask.ip, node_to_ask.port)
        result = await self.store(address, self.source_node.id, key, value,ip,port)
        return self.handle_call_response(result, node_to_ask)

    def welcome_if_new(self, node):
        """
        Given a new node, send it all the keys/values it should be storing,
        then add it to the routing table.

        @param node: A new node that just joined (or that we just found out
        about).

        Process:
        For each key in storage, get k closest nodes.  If newnode is closer
        than the furtherst in that list, and the node for this server
        is closer than the closest in that list, then store the key/value
        on the new node (per section 2.5 of the paper)
        """
        if not self.router.is_new_node(node):
            return

        log.info("never seen %s before, adding to router", node)
        for key, value in self.storage:
            keynode = Node(digest(key))
            neighbors = self.router.find_neighbors(keynode)
            if neighbors:
                last = neighbors[-1].distance_to(keynode)
                new_node_close = node.distance_to(keynode) < last
                first = neighbors[0].distance_to(keynode)
                this_closest = self.source_node.distance_to(keynode) < first
            if not neighbors or (new_node_close and this_closest):
                asyncio.ensure_future(self.call_store(node, key, value))
        self.router.add_contact(node)

    def handle_call_response(self, result, node):
        print(f'handle_call_response,result={result},node={node}')
        """
        If we get a response, add the node to the routing table.  If
        we get no response, make sure it's removed from the routing table.
        """
        if not result[0]:
            log.warning("no response from %s, removing from router", node)
            self.router.remove_contact(node)
            return result

        log.warning("got successful response from %s", node)
        self.welcome_if_new(node)
        return result
