![Pwned Screen](.images/Screenshot.png)

Platform :
Hack the Box

Box :
Cypher

Difficulty :
Medium

OS :
Linux 

Created by: 
Techromancer

*Overview*

Cypher is a medium-difficulty Linux machine from HackTheBox The machine involves:

-Discovering Java class files on the website and decompiling them.

-Identifying a vulnerable custom function capable of executing a reverse shell.

-Exploiting a rare Cypher injection vulnerability in the Neo4j graph database.

-Escalating privileges through a misconfigured Bbot recon scanner to retrieve the root flag.

-------------------------------------------------------------------------------------------------------
*Starting with an Nmap scan to identify open ports:*
Port 22 (SSH): Running OpenSSH 9.6p1 on Ubuntu.

Port 80 (HTTP): Hosting an Nginx 1.24.0 web server.

The website is accessible at http://cypher.htb/, so we add it to /etc/hosts.

```bash
┌──(kali㉿kali)-[~]
└─$ sudo nmap -Pn -A 10.10.11.57                        
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-15 03:52 EDT
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 03:52 (0:00:00 remaining)
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 03:52 (0:00:07 remaining)
Stats: 0:00:15 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 100.00% done; ETC: 03:52 (0:00:00 remaining)
Stats: 0:02:09 elapsed; 0 hosts completed (1 up), 1 undergoing Traceroute
Traceroute Timing: About 32.26% done; ETC: 03:54 (0:00:00 remaining)
Stats: 0:02:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.54% done; ETC: 03:54 (0:00:00 remaining)
Stats: 0:02:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.60% done; ETC: 03:54 (0:00:00 remaining)
Stats: 0:02:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.60% done; ETC: 03:54 (0:00:00 remaining)
Stats: 0:02:13 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.60% done; ETC: 03:54 (0:00:00 remaining)
Stats: 0:02:39 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.65% done; ETC: 03:55 (0:00:00 remaining)
Stats: 0:02:39 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.65% done; ETC: 03:55 (0:00:00 remaining)
Stats: 0:02:40 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.65% done; ETC: 03:55 (0:00:00 remaining)
Nmap scan report for cypher.htb (10.10.11.57)
Host is up (1.2s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: GRAPH ASM
|_http-server-header: nginx/1.24.0 (Ubuntu)
Aggressive OS guesses: HP P2000 G3 NAS device (97%), Linux 5.0 (95%), Linux 5.0 - 5.4 (95%), OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34) (93%), OpenWrt White Russian 0.9 (Linux 2.4.30) (93%), OpenWrt Kamikaze 7.09 (Linux 2.6.22) (93%), Linux 4.15 - 5.8 (93%), Linux 5.3 - 5.4 (92%), Linux 2.6.32 (92%), AVM FRITZ!Box (FritzOS 6.20) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   154.10 ms 10.10.16.1
2   153.75 ms cypher.htb (10.10.11.57)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                       
Nmap done: 1 IP address (1 host up) scanned in 165.36 seconds   
```
-------------------------------------------------------------------------------------------------------
The website has title “GRAPH ASM” and presents itself as “revolutionary Attack Surface Management solution that harnesses the power of proprietary graph technology to map your organization’s digital landscape.”

When I looked at the source code, there was a comment that caught my attention. A quote from a potential user “TheFunky1”.



![Pwned Screen](.images/1.png)
In the source code for login page, I found a script that makes POST request to “/api/auth” endpoint, suggesting there’s an API, which opened doors for more attack vectors.


![Pwned Screen](.images/2.png)

I continued with directory fuzzing using Gobuster.
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u "http://cypher.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 64 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cypher.htb
[+] Method:                  GET
[+] Threads:                 64
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 4562]
/login                (Status: 200) [Size: 3671]
/about                (Status: 200) [Size: 4986]
/demo                 (Status: 307) [Size: 0] [--> /login]
/api                  (Status: 307) [Size: 0] [--> /api/docs]
/testing              (Status: 301) [Size: 178] [--> http://cypher.htb/testing/]
```
Aside from a few well-known directories, I discovered a "demo" page that redirected me to the "login" page and an "api" page leading to the documentation. However, the "testing" page caught my attention. There, I found a mysterious Java Archive (JAR) file named "custom_apoc_extension," which I quickly downloaded.  

APOC, short for "Awesome Procedures on Cypher," is a library of procedures and functions designed for Neo4j, a widely used graph database. It enhances Neo4j's capabilities by offering a variety of additional features not included in the core database, such as tools for data import/export, graph algorithms, and data transformation. 

![Pwned Screen](.images/3.png)





