**#** **A friendly warning**

In the source code, I published some information of my frp server. Like my server's IP. If you want to access the website, you can go [SDSZ computer science club](sdszalg.cn).

If you use it as a free tool to do NAT traversal, emm, OK... so far

***\*****However, if you attack our server like DDOS, killer Jack may love you*****\***

**#** **Overview**

The program should run in Windows.

**##** **files' descriptions**

The main code is in main.py

Everything related to frp is in "connect" folder

***\*****Note!!!*****\*** I changed the rpcudp and kademlia module because they have bugs(Maybe is my bug? Who cares) like the buffer is None instead of an empty dequeue. So I uploaded the asyncio and kademlia modules on the GitHub

Have you ever wondered why he knows him? Like your TOEFL class' classmate's high school classmate is your middle school's classmate, our project "The-Emergence" is used to solve these kinds of issue