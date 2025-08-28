#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

echo " Started at: $(date)"
echo "=============================================="

echo -e "\n${CYAN}[+] SYSTEM INFORMATION [+]${NC}"
echo "----------------------------------------------"

echo -e "${BLUE}[i] Kernel version:${NC}"
uname -r 2>/dev/null

echo -e "${BLUE}[i] OS info:${NC}"
cat /etc/issue /etc/os-release 2>/dev/null | grep -E "(PRETTY_NAME|NAME|VERSION)=" | head -n 3

echo -e "${BLUE}[i] Architecture:${NC}"
arch 2>/dev/null || uname -m 2>/dev/null

echo -e "${BLUE}[i] Hostname:${NC}"
hostname 2>/dev/null

echo -e "${BLUE}[i] Kernel exploit suggestions:${NC}"
uname -r 2>/dev/null | awk -F. '{print "Search: linux kernel " $1 "." $2 " exploit"}'

echo -e "\n${CYAN}[+] USER INFORMATION [+]${NC}"
echo "----------------------------------------------"

echo -e "${BLUE}[i] Current user/groups:${NC}"
id 2>/dev/null

echo -e "${BLUE}[i] Logged in users:${NC}"
whoami 2>/dev/null && w 2>/dev/null | head -n 5

echo -e "${BLUE}[i] Last logged in users:${NC}"
last 2>/dev/null | head -n 5

echo -e "${BLUE}[i] Users with UID 0 (root):${NC}"
grep -v -E "^#" /etc/passwd 2>/dev/null | awk -F: '$3 == 0 {print $1}' 2>/dev/null

echo -e "${BLUE}[i] Checking user history files:${NC}"
find /home /root -name ".*_history" -readable -type f 2>/dev/null | head -n 5


echo -e "\n${CYAN}[+] SUDO CHECKS [+]${NC}"
echo "----------------------------------------------"
if command -v sudo >/dev/null 2>&1; then
    echo -e "${BLUE}[i] Sudo version:${NC}"
    sudo -V 2>/dev/null | head -n 1

    echo -e "${BLUE}[i] Can we run sudo without password?${NC}"

    timeout 2 bash -c 'echo "" | sudo -S -l 2>/dev/null' | grep -E "(NOPASSWD|ALL)" | grep -v "not allowed"
    if [ ${PIPESTATUS[0]} -eq 124 ]; then
        echo "Sudo check timed out (likely requires a password)."
    fi
else
    echo "Sudo not found."
fi

echo -e "\n${CYAN}[+] CAPABILITIES [+]${NC}"
echo "----------------------------------------------"
if command -v getcap >/dev/null 2>&1; then
    echo -e "${BLUE}[i] Interesting capabilities:${NC}"
    getcap -r / 2>/dev/null | grep -v "/usr/lib" | head -n 10
else
    echo "getcap not found."
fi

echo -e "\n${CYAN}[+] SUID/GUID FILES [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Non-standard SUID files (excluding common ones):${NC}"
find / -perm -4000 -type f 2>/dev/null | grep -E -v "(/usr/bin/passwd|/usr/bin/sudo|/usr/bin/find|/usr/bin/base64|/usr/bin/bash|/usr/bin/mount|/usr/bin/su|/usr/bin/newgrp|/usr/bin/chsh|/usr/bin/chfn|/usr/bin/gpasswd|/usr/lib/openssh/|/usr/lib/dbus-1.0/|/usr/lib/eject/)" | head -n 15

echo -e "${BLUE}[i] Non-standard GUID files:${NC}"
find / -perm -2000 -type f 2>/dev/null | grep -E -v "(/usr/bin/at|/usr/bin/crontab|/usr/bin/wall|/usr/bin/ssh-agent|/usr/bin/expiry|/usr/bin/traceroute|/sbin/unix_chkpwd|/usr/bin/mlocate)" | head -n 10

echo -e "${BLUE}[i] Known exploitable SUID binaries:${NC}"
find / -perm -4000 -type f 2>/dev/null | xargs -I {} sh -c 'echo -n "{}: "; {} --help 2>&1 | head -1' 2>/dev/null | grep -E "(vim|nmap|find|bash|python|perl|ruby|node)" | head -n 5

echo -e "\n${CYAN}[+] CRON JOBS [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] System cron jobs:${NC}"
ls -la /etc/cron* 2>/dev/null
echo -e "${BLUE}[i] User cron jobs (if allowed):${NC}"
crontab -l 2>/dev/null || echo "Cannot read user crontab."
echo -e "${BLUE}[i] Writable cron directories/files:${NC}"
find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null 2>/dev/null | head -n 5

echo -e "${BLUE}[i] Writable cron scripts:${NC}"
find /etc/cron* /var/spool/cron* -type f -writable -exec ls -la {} \; 2>/dev/null | head -n 5

echo -e "\n${CYAN}[+] WORLD-WRITABLE FILES [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] World-writable files (excluding /proc and /sys):${NC}"
find / -xdev -type f -perm -o=w 2>/dev/null | grep -E -v "(/proc/|/sys/|/dev/|/run/)" | head -n 10

echo -e "\n${CYAN}[+] CRITICAL WRITABLE FILES [+]${NC}"
echo "----------------------------------------------"
critical_files=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/crontab" "/root/.ssh/authorized_keys" "/etc/ssh/sshd_config" "/etc/init.d" "/etc/systemd/system" "/etc/hosts" "/etc/ld.so.conf" "/etc/ld.so.preload")
for cfile in "${critical_files[@]}"; do
    if [ -w "$cfile" ]; then
        echo -e "${RED}[!] CRITICAL: $cfile is writable! ${NC}"
    else
        if [ -f "$cfile" ]; then
            perms=$(ls -la "$cfile" 2>/dev/null | awk '{print $1 " " $3 ":"$4}')
            echo -e "${GREEN}[+] $cfile permissions: $perms ${NC}"
        fi
    fi
done

echo -e "\n${CYAN}[+] NETWORK INFORMATION [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Network interfaces:${NC}"
(ip addr show 2>/dev/null || ifconfig 2>/dev/null) | grep -E "(inet|ether)" | grep -v "127.0.0.1" | head -n 6
echo -e "${BLUE}[i] Current connections:${NC}"
(netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null) | grep -E "(LISTEN|ESTABLISHED)" | head -n 5
echo -e "${BLUE}[i] ARP table:${NC}"
arp -a 2>/dev/null | head -n 3

echo -e "${BLUE}[i] Routing table:${NC}"
(ip route 2>/dev/null || route -n 2>/dev/null) | head -n 5

echo -e "\n${CYAN}[+] PROCESS INFORMATION [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Running processes (as root):${NC}"
ps aux 2>/dev/null | grep root | grep -v "\[" | head -n 5

echo -e "\n${CYAN}[+] ENVIRONMENT VARIABLES [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Interesting environment variables:${NC}"
env 2>/dev/null | grep -E "(PATH|LD_|SHELL|SUDO|USER|HOME|PWD)" | head -n 10

echo -e "\n${CYAN}[+] CREDENTIAL SEARCH [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Searching for common credential files:${NC}"
important_files=(".bash_history" ".ssh/id_rsa" ".ssh/authorized_keys" ".mysql_history" ".profile" ".bashrc" ".env" "config.php" "database.yml" "*.pem" "*.key" "*.bak" "*.old")
for pattern in "${important_files[@]}"; do
    found=$(find /home /root /var /opt -name "$pattern" -readable -type f 2>/dev/null | head -n 2)
    if [ ! -z "$found" ]; then
        echo -e "${YELLOW}[FOUND] $pattern files:${NC}"
        echo "$found"
    fi
done

echo -e "\n${CYAN}[+] SOFTWARE & SERVICES [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Interesting services:${NC}"
tools=("docker" "kubectl" "python" "python3" "nc" "ncat" "netcat" "nmap" "aws" "gcc" "php" "node" "npm" "perl" "ruby")
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "$tool is installed."
    fi
done

echo -e "\n${CYAN}[+] EXPLOITABLE BINARIES CHECK [+]${NC}"
echo "----------------------------------------------"
exploitable_binaries=("apt" "apt-get" "ash" "awk" "base64" "bash" "busybox" "cat" "cp" "cpio" "csh" "curl" "dash" "date" "dd" "docker" "ed" "emacs" "env" "expect" "find" "flock" "ftp" "gawk" "gdb" "git" "head" "ionice" "jjs" "jq" "jrunscript" "ksh" "ld.so" "less" "lua" "make" "more" "mv" "nano" "nc" "netcat" "nice" "nl" "nmap" "node" "od" "perl" "php" "pico" "python" "python3" "rlwrap" "rpm" "rpmquery" "rsync" "ruby" "run-parts" "scp" "script" "sed" "setarch" "sftp" "sh" "socat" "sort" "sqlite3" "ssh" "stdbuf" "strace" "tail" "tar" "taskset" "tclsh" "tee" "telnet" "tftp" "time" "timeout" "ul" "unexpand" "uniq" "unshare" "vi" "vim" "watch" "wget" "xargs" "xxd" "zip" "zsh")
echo -e "${BLUE}[i] Checking for known exploitable binaries:${NC}"
for bin in "${exploitable_binaries[@]}"; do
    if command -v "$bin" >/dev/null 2>&1; then
        location=$(which "$bin" 2>/dev/null)
        echo "[+] $bin found at: $location"
    fi
done

echo -e "\n${CYAN}[+] WRITABLE FILES OWNED BY ROOT [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Files owned by root that are writable by current user:${NC}"
find / -user root -writable -type f 2>/dev/null | grep -E -v "(/proc/|/sys/|/dev/|/run/|/var/log/|/var/cache/|/var/tmp/|/tmp/)" | head -n 15

echo -e "${BLUE}[i] Directories owned by root that are writable by current user:${NC}"
find / -user root -writable -type d 2>/dev/null | grep -E -v "(/proc/|/sys/|/dev/|/run/|/var/log/|/var/cache/|/var/tmp/|/tmp/)" | head -n 10

echo -e "\n${CYAN}[+] MOUNTED FILESYSTEMS [+]${NC}"
echo "----------------------------------------------"
echo -e "${BLUE}[i] Mounted filesystems:${NC}"
df -h 2>/dev/null | grep -v "tmpfs" | head -n 6
echo -e "${BLUE}[i] No_root_squash or unusual mount options:${NC}"
mount 2>/dev/null | grep -E "(no_root_squash|rw,)" | head -n 3

echo -e "\n${CYAN}[+] DOCKER CHECKS [+]${NC}"
echo "----------------------------------------------"
if command -v docker >/dev/null 2>&1; then
    echo -e "${BLUE}[i] Docker version:${NC}"
    docker --version 2>/dev/null
    echo -e "${BLUE}[i] Can we run docker?${NC}"
    docker ps 2>/dev/null | head -n 3
    if [ $? -eq 0 ]; then
        echo "Docker accessible - check for privilege escalation via container escape"
    fi
else
    echo "Docker not found or not accessible."
fi

echo -e "\n${CYAN}[+] LANGUAGE INTERPRETERS [+]${NC}"
echo "----------------------------------------------"
interpreters=("python" "python3" "perl" "ruby" "node" "php" "lua" "awk" "expect")
for interp in "${interpreters[@]}"; do
    if command -v "$interp" >/dev/null 2>&1; then
        version=$($interp --version 2>&1 | head -n 1)
        echo "$interp: $version"
    fi
done

echo -e "\n${GREEN}[+] SCAN COMPLETE [+]${NC}"
echo "=============================================="
echo " Finished at: $(date)"
echo -e "${MAGENTA}"
echo " Next steps:"
echo " 1. Investigate any 'CRITICAL' or 'Writable' findings."
echo " 2. Check for exploits for the kernel version."
echo " 3. Research any unusual SUID/GUID binaries."
echo " 4. Look for passwords in any found files."
echo " 5. Check if any interpreters can be used for shell escape."
echo " 6. Investigate writable service files or cron jobs."
echo " 7. Check for exploitable binaries from the list."
echo " 8. Look for writable files owned by root."
echo -e "${NC}"
echo "=============================================="
