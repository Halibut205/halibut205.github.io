---
title: "Cyber Defenders - XXE Infiltration Writeup"
date: 2026-06-26 16:09:00 +0700
categories: [Cyber Defenders, Network Forensics]
tags: [cyber-defenders, network-forensics, writeup]
---

**Category**: Network Forensics

**Checkout the lab here**: <https://cyberdefenders.org/blueteam-ctf-challenges/xxe-infiltration/>

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image.png)

<aside markdown="1">
➡️ Description

An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.

Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.

</aside>

> **Q1: Identifying the open ports discovered by an attacker helps us understand which services are exposed and potentially vulnerable. Can you identify the highest-numbered port that is open on the victim's web server?**
> 

According to the question “**the highest-numbered port that is open”**, in the TCP stream, if both a SYN and ACK packet are sent, the server is responding to a connection request (which means the port is open). By using `tcp.flags.syn eq 1 and tcp.flags.ack eq 1`, I can check out those open services.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%201.png)

In any services that show up here, SQL should not be the one. We already see the port, but i still try to filter out SQL service to see what is going on using `mysql`.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%202.png)

**Answer: 3306**

> **Q2: By identifying the vulnerable PHP script, security teams can directly address and mitigate the vulnerability. What's the complete URI of the PHP script vulnerable to XXE Injection?**
> 

I was doing a bit of research and found out what XXE Injection actually means. An XXE vulnerability occurs when a server processes XML input that includes a malicious external entity reference, and the server's XML parser is configured to fetch and process that external resource.

According to Q2, XML input was lying inside a PHP file and it was uploaded (POST) to the server, to filter it out I used `http.request.uri contains ".php"  && http.request.method eq POST`

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%203.png)

Follow HTTP stream to make sure the file was suspicious.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%204.png)

**Answer: /review/upload.php**

> **Q3: To construct the attack timeline and determine the initial point of compromise. What's the name of the first malicious XML file uploaded by the attacker?**
> 

We can see the file name right away in the HTTP steam last question.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%205.png)

**Answer: TheGreatGatsby.xml**

> **Q4: Understanding which sensitive files were accessed helps evaluate the breach's potential impact. What's the name of the web app configuration file the attacker read?**
> 

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%206.png)

By moving up a few streams, we can see that the attacker was trying to interact with several files. One of them was `config.php`.

**Answer: config.php**

> **Q5: To assess the scope of the breach, what is the password for the compromised database user?**
> 

And just like that, by reading the config file, the attacker found the credentials for a database user.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%207.png)

**Answer: config.php**

> **Q6: Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?**
> 

I noticed that the config file was being read around this time, so the login request to SQL server must have occurred afterward.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%208.png)

I’m filtered out all the connection request to MySQL by using `mysql`, And find out the suspicious packet.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%209.png)

**Answer: 2024-05-31 12:08**

> **Q7: To eliminate the threat and prevent further unauthorized access, can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?**
> 

Return to the webshell, we have one last entry left to go. Look into the final POST request and inspect the HTTP Stream, we can see a file named `booking.php` uploaded to the server.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%2010.png)

By using just `http.request`, I can see the full picture. Now that we can see `booking.php` was a shellcode file.

![image.png](/assets/img/cyber-defenders/xxe-infiltration/image%2011.png)

**Answer: booking.php**
