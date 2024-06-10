The program should run in Windows.

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
