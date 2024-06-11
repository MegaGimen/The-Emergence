# 小小的提示

在源代码中，我上传了一些和我的frp内网穿透服务器有关信息，比如我服务器的ip，如果你想看我服务器挂载的网站是什么的话，你可以访问[SDSZ 计算机科学社](sdszalg.cn).

如果你想把它做一个免费且不实名的内网穿透工具的话，只要服务器负载还好，其实没问题

**请不要DDOS攻击服务器，因为老大哥正在看着你**

# 总览

这个项目目前只能在我Windows中运行

## 几个文件的描述

主程序是main.py

所有和内网穿透有关的都在“connect”这个文件夹下

**注意！**我在原生的rpcudp和kademlia这两个库上进行了一些修改（主要是因为有很多bug，比如rpcudp中有可能缓存是none而不是空的双端队列

你是否曾经发问过，哎ta是怎么认识ta的？比如你高中同学的邻居是你初中同学，这种情况在朋友圈中尤其多见，点赞和评论架起了我们之间的桥梁。而此时你会感慨：“世界真小！”而这个开源项目“涌现”则旨在解决这类问题

“涌现”这个词来源于凯文凯利的《失控》，他强调了“自生自发地涌现出秩序”。而kademlia这个分布式哈希表的算法和涌现特别像，很多节点只是遵循简单的规则，却涌现出了一个复杂的网络系统

为了保护个人隐私，使用者可以在新建关系时决定是否公开关系，如果不公开的话，就会用RSA算法生成一个公钥私钥对，将私钥存储在本地的钥匙串中，而公钥用来加密这个关系并广播（没有私钥解密，得到的不过是一堆乱码），如果公开的话，就会直接广播到全网，这意味着，所有人都有可能在查询认识关系路径时查询到这一个关系。而如果不公开的话，只有有这个私钥的人才能查到

举个例子，现在有一个简单的关系图：

``` text
1. Sam<--(小时候的邻居)--> Kevin
2. Sam<--(高中同学)--> Jacob
3. Jacob<--(网友)--> Jaycee
4. Kevin<--(NOIP春季训练队友)--> Paul
```

第三和第四个关系是公开的，所有所有人都有可能在检索自己的关系是查到这条路径

比如你是Sam，你公开了关系2，而关系1被你锁定了，锁定的公钥是 $pk$ ，其相应的私钥是$sk$，私钥会存在本地钥匙串上，**没有你本地的私钥，任何人都无法查询到这个关系，包括我们开发者**

如果Paul想要查他和Sam的关系，他是查不到的，因为他没有获得关系1的权限，所以这个认识路径链在关系1断开了。

如果Jaycee想要知道她和Sam是怎么认识的，因为关系2、3、4是公开的，所以她能查到：

``` text
Sam<--(高中同学)-->Jacob<--(网友)--> Jaycee
```

如果Paul和Sam是好友而Sam想让他知道关系1的话，那么Paul可以把**针对关系1的** $sk$发给Sam，而此时Paul就可以查到了

# future development roadmap（使用“roadmap”是为了纪念sunorange）

目前，我们还没有开发使用弹窗显示输出的功能（也就是目前还是在控制台中输出）。而且现在的返回字符串还是一个列表，比如["高中同学","网友"]这种，希望可以优化

同时，我希望能引入一些机制让p2p网络更灵活地处理节点快速进出，因为没人会把自己的电脑一直打开着来当一个节点

我也希望让它支持更多的UI语言，包括中文、英文

![yx](./yx.png)

# A friendly warning

In the source code, I published some information of my frp server. Like my server's IP. If you want to access the website, you can go [SDSZ computer science club](sdszalg.cn).

If you use it as a free tool to do NAT traversal, emm, OK... so far

**However, if you attack our server like DDOS, killer Jack may love you**

# Overview

The program should run in Windows.

## files' descriptions

The main code is in main.py

Everything related to frp is in "connect" folder

**Note!!!** I changed the rpcudp and kademlia module because they have bugs(Maybe is my bug? Who cares) like the buffer is None instead of an empty dequeue. So I uploaded the asyncio and kademlia modules on the GitHub

Have you ever wondered why he knows him? Like your TOEFL class' classmate's high school classmate is your middle school's classmate, our project "The-Emergence" is used to solve these kinds of issue

The word "Emergence" is derived from "emerge spontaneously", which is hightly praised by Kevin Kelly in his book Out of Control and by Hayek who represent the neoliberalism. The reason why we use "emerge" is that we applied Kademlia, a distributed hash table(DHT) in this project to let many nodes to maintain a hash table which store the relationship. Kademlia is a sort of the "emergence"---every node followed some single rules, but the whole complex system can be built based on them.

In order to keep personal secret, one can choose whether publish the new relationship or not while updating the relationship. If you prefer keeping private, your relationship information will be encrypted by a public key and sent. Note, **anyone who has the secret key paired with the public key can retrieve the relationship**

Here's an simple example:
The real relationship map is:
``` text
1. Sam<--(neighbor in childhood)--> Kevin
2. Sam<--(SAT classmate)--> Jacob
3. Jacob<--(online friend)--> Jaycee
4. Kevin<--(team members in USACO summer camp)--> Paul
```
and relationship 3 and 4 is published, so everyone on the route may find it

Say that you're Sam, you publish relationship 2 in public but 1 in private, which is encrypted by $pk$ and $sk$ .

So if Paul want to know the relationship between him and Sam, the result is None because he does't have permission to "know" that Sam and Kevin are neighbors in childhood, and the "knowing route" breaks at relationship 1

If Jaycee want to know how she and Sam know, because relationship 2,3,4 are published, the query will return:

``` text
Sam<--(SAT classmate)-->Jacob<--(online friend)--> Jaycee
```

Note, if Paul is Sam's good friend and Sam wants him to know, he can send Sam his $sk$ **towards this specific relationship** and Paul can know find it.

# future dev road map (the term "road map" is aimed at showing respect to Sunorange, miss you, xjc)

Currently, we haven't dev the messagebox's show and we want to make the showing str beautiful. It's know sth like: "[SAT classmate, online friend]", the return is a list, but who likes seeing list in dark console? (If your theme is other color, forget it)

Besides, I hope to make the network healthier by appyling some strategies on it.

I want the project to accept more UI's languages, including Chinese and English
