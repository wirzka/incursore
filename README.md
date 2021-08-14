# Incursore
```bash
     ____                                        
    /  _/___ _______  ________________  ________
   / // __ \/ ___/ / / / ___/ ___/ __ \/ ___/ _ \
 _/ // / / / /__/ /_/ / /  (__  ) /_/ / /  /  __/
/___/_/ /_/\___/\__,_/_/  /____/\____/_/   \___/
                     @wirzka     
```
*Incursore* will raid the target for you.

It came out from *nmapAutomator* to be more suited for the OSCP environment.

## TOC
- [Lazy here](#tldr)
- [Features and changes](#features-and-changes)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Future features](#future-features)

## TL;DR
While *incursore* has born from *nmapAutomator*, it is **not** *nmapAutomator*. The script from @21y4d is great, but sometimes it's too slow (due to nikto).
So, from just removing nikto I found myself tweaking it a lot, that's why I decided to rename it to incursore and to publish it under a new repo and name.
Hope you'll find it useful.
## Features and changes
*Incursore* has the following features and changes:
- It immmediately runs a full TCP port scans
- It asks to the user to run with sudo in order to run a SYN Scan instead of a Connect Scan
- It automatically try to bruteforce FTP services
- It automatically take screenshot of HTTP homepages using *cutycapt*
- It runs *ffuf* instead of *gobuster*
- It does not run *nikto*
- It has not the remote capabilities

## Requirements
*Incursore*'s requirements are the following:
|      tool      |      scope      | official link |
|:--------------:|:---------------:|:-------------:|
|      nmap      |   recon/enum    | https://nmap.org/              |
|  nmap vulners  |      recon      |   https://github.com/vulnersCom/nmap-vulners            |
|      ffuf      |    web enum     |  https://github.com/ffuf/ffuf             |
|    sslscan     |    web enum     |  https://github.com/rbsec/sslscan             |
|    joomscan    |    web enum     | https://github.com/OWASP/joomscan              |
|     wpscan     |    web enum     |   https://github.com/wpscanteam/wpscan            |
|   droopescan   |    web enum     | https://github.com/droope/droopescan              |
|    cutycapt    |    web enum     |http://cutycapt.sourceforge.net/               |
|     smbmap     |    smb enum     | https://github.com/ShawnDEvans/smbmap              |
|   enum4linux   |    smb enum     |   https://github.com/CiscoCXSecurity/enum4linux            |
|   snmp-check   |    snmp enum    | https://www.nothink.org/codes/snmpcheck/index.php              |
|    snmpwalk    |    snmp enum    |https://linux.die.net/man/1/snmpwalk               |
|      odat      | oracle db recon |   https://github.com/quentinhardy/odat            |
|   ldapsearch   |    ldap enum    |   https://linux.die.net/man/1/ldapsearch            |
|    dnsrecon    |    dns enum     | https://github.com/darkoperator/dnsrecon              |
| smtp-user-enum |    smtp enum    | https://github.com/pentestmonkey/smtp-user-enum              |
|     hydra      | ftp bruteforce  | https://github.com/vanhauser-thc/thc-hydra              |


The majority of them is already present in pentesting distro like Parrot OS and Kali Linux.

## Installation
```bash
git clone https://github.com/wirzka/incursore.git
sudo ln -s $(pwd)/incursore/incursore.sh /usr/local/bin/
```
## Usage
```bash
$ incursore.sh -h
     ____                                        
    /  _/___ _______  ________________  ________
   / // __ \/ ___/ / / / ___/ ___/ __ \/ ___/ _ \
 _/ // / / / /__/ /_/ / /  (__  ) /_/ / /  /  __/
/___/_/ /_/\___/\__,_/_/  /____/\____/_/   \___/
                     @wirzka                      

Usage: incursore.sh -H/--host <TARGET-IP> -t/--type <TYPE>
Optional: [-d/--dns <DNS SERVER>] [-o/--output <OUTPUT DIRECTORY>]

Scan Types:
        Port    : Shows all open ports
        Script  : Runs a script scan on found ports
        UDP     : Runs a UDP scan "requires sudo"
        Vulns   : Runs CVE scan and nmap Vulns scan on all found ports
        Recon   : Suggests recon commands, then prompts to automatically run them
        All     : Runs all the scans

inspired by @21y4d gently modified by @wirzka
```
## Future Features
- Generally increasing auto reconnaissance based on discovered services.
