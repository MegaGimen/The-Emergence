![yx](yx.png)

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
