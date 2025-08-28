# Linux Privilege Escalation Enumeration Script

## 📌 Overview
This Bash script automates the enumeration of a Linux system for **privilege escalation opportunities**.  
It gathers information about the system, users, permissions, services, and potential misconfigurations that an attacker or penetration tester could leverage to escalate privileges.

The output is color-coded for readability and grouped into logical sections, with **recommended next steps** provided at the end.

---

## ⚙️ Features
The script collects information across multiple categories:

- **System Information**
  - Kernel version
  - OS details
  - Architecture & hostname
  - Kernel exploit search hints

- **User Information**
  - Current user & groups
  - Logged-in and last logged-in users
  - Root accounts
  - History files

- **Sudo Checks**
  - Sudo version
  - NOPASSWD or unrestricted sudo access

- **Capabilities**
  - Checks for uncommon Linux capabilities

- **SUID/SGID Files**
  - Non-standard SUID/SGID binaries
  - Known exploitable SUID binaries

- **Cron Jobs**
  - System & user cron jobs
  - Writable cron files and scripts

- **Writable Files**
  - World-writable files
  - Critical config files (e.g., `/etc/passwd`, `/etc/shadow`)
  - Files/directories owned by root but writable by the current user

- **Network Information**
  - Interfaces, connections, ARP, and routing table

- **Processes**
  - Root-owned processes

- **Environment Variables**
  - PATH, LD_* and other potentially exploitable variables

- **Credential Search**
  - Looks for sensitive files (`.ssh/id_rsa`, `.bash_history`, `.env`, `config.php`, etc.)

- **Software & Services**
  - Detects tools like `docker`, `kubectl`, `nmap`, `aws`, `gcc`, etc.

- **Exploitable Binaries**
  - Cross-checks installed binaries against a list of known shell escape candidates (e.g., `vi`, `awk`, `python`)

- **Mounted Filesystems**
  - Highlights `no_root_squash` and writable mount points

- **Docker Checks**
  - Version info
  - Tests if user can run Docker commands

- **Language Interpreters**
  - Checks versions of `python`, `perl`, `ruby`, `php`, etc.

---

## ⚠️ Disclaimer
This script is intended for educational purposes and authorized penetration testing only.
Running it on systems without permission may be illegal.
