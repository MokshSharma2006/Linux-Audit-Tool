#!/bin/bash

# Linux Security Audit Tool
# Version: 1.0
# Author: Moksh Sharma
# Date: 2025/07/20

# Output file
OUTPUT_FILE="linux_security_audit_$(date +%Y%m%d_%H%M%S).txt"
TEMP_FILE="/tmp/security_audit_temp.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Header
echo "Linux Security Audit Report" > $OUTPUT_FILE
echo "Generated on: $(date)" >> $OUTPUT_FILE
echo "Hostname: $(hostname)" >> $OUTPUT_FILE
echo "Kernel Version: $(uname -r)" >> $OUTPUT_FILE
echo "Distribution: $(lsb_release -d | cut -f2-)" >> $OUTPUT_FILE
echo "==========================================" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE

# Function to check and append results
check_append() {
    local title=$1
    local command=$2
    local description=$3
    
    echo -e "${YELLOW}[*] Checking: $title${NC}"
    echo "" >> $OUTPUT_FILE
    echo "=== $title ===" >> $OUTPUT_FILE
    echo "Description: $description" >> $OUTPUT_FILE
    echo "---" >> $OUTPUT_FILE
    eval "$command" >> $OUTPUT_FILE 2>&1
    echo "---" >> $OUTPUT_FILE
}

# 1. User Account Checks
check_append "User Accounts" "cat /etc/passwd" "List of all user accounts"
check_append "Password Hashes" "sudo cat /etc/shadow" "Password hashes (requires sudo)"
check_append "Empty Password Accounts" "sudo awk -F: '(\$2 == \"\") {print \$1}' /etc/shadow" "Accounts with empty passwords"
check_append "UID 0 Accounts" "awk -F: '(\$3 == 0) {print \$1}' /etc/passwd" "Accounts with UID 0 (root)"
check_append "Last Logins" "lastlog" "Last login information for all users"
check_append "Failed Login Attempts" "sudo lastb | head -20" "Recent failed login attempts"
check_append "Password Aging" "sudo chage -l root && echo && sudo grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs" "Password aging configuration"

# 2. SSH Configuration
check_append "SSH Configuration" "sudo cat /etc/ssh/sshd_config | grep -v '^#\|^$'" "SSH server configuration"
check_append "SSH Root Login" "sudo grep -i 'PermitRootLogin' /etc/ssh/sshd_config" "SSH root login permission"
check_append "SSH Protocol Version" "sudo grep -i 'Protocol' /etc/ssh/sshd_config" "SSH protocol version"

# 3. Network Security
check_append "Listening Services" "sudo netstat -tulnp" "Services listening on network ports"
check_append "Firewall Status" "sudo iptables -L -n -v" "IPTables firewall rules"
check_append "UFW Status" "sudo ufw status verbose" "Uncomplicated Firewall status"
check_append "Network Connections" "sudo netstat -atnp" "Active network connections"
check_append "Routing Table" "sudo route -n" "System routing table"
check_append "ARP Table" "sudo arp -a" "ARP table entries"

# 4. System Services
check_append "Running Services" "sudo systemctl list-units --type=service --state=running" "Currently running services"
check_append "Enabled at Boot" "sudo systemctl list-unit-files --state=enabled" "Services enabled at boot"
check_append "Open Files" "sudo lsof +L1" "List of open files"

# 5. File System and Permissions
check_append "World Writable Files" "sudo find / -xdev -type f -perm -0002 -exec ls -l {} + 2>/dev/null" "World writable files"
check_append "SUID/SGID Files" "sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -l {} + 2>/dev/null" "SUID/SGID files"
check_append "Unowned Files" "sudo find / -xdev \( -nouser -o -nogroup \) -exec ls -l {} + 2>/dev/null" "Files with no owner or group"
check_append "/tmp Permissions" "ls -ld /tmp" "/tmp directory permissions"
check_append "Critical File Permissions" "ls -l /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config" "Permissions on critical files"

# 6. Kernel and System Configuration
check_append "Kernel Parameters" "sudo sysctl -a 2>/dev/null" "Kernel parameters"
check_append "Core Dumps" "sudo sysctl fs.suid_dumpable" "Core dump configuration"
check_append "ASLR Status" "sudo cat /proc/sys/kernel/randomize_va_space" "Address Space Layout Randomization status"

# 7. Logging and Auditing
check_append "Auditd Status" "sudo systemctl status auditd" "Audit daemon status"
check_append "Audit Rules" "sudo auditctl -l" "Current audit rules"
check_append "System Logs" "sudo ls -l /var/log/" "System log files"
check_append "Recent Auth Logs" "sudo tail -50 /var/log/auth.log 2>/dev/null || sudo tail -50 /var/log/secure 2>/dev/null" "Recent authentication logs"

# 8. Package and Update Information
check_append "Installed Packages" "sudo dpkg -l 2>/dev/null || sudo rpm -qa 2>/dev/null" "List of installed packages"
check_append "Update Status" "sudo apt list --upgradable 2>/dev/null || sudo yum list updates 2>/dev/null" "Available package updates"

# 9. Cron Jobs
check_append "System Cron Jobs" "sudo ls -la /etc/cron*" "System cron directories"
check_append "User Cron Jobs" "sudo ls -la /var/spool/cron/crontabs" "User cron jobs"
check_append "Cron Jobs Content" "sudo cat /etc/crontab && echo && for user in $(cut -f1 -d: /etc/passwd); do sudo crontab -u $user -l 2>/dev/null; done" "Contents of cron jobs"

# 10. SELinux/AppArmor
check_append "SELinux Status" "sudo sestatus 2>/dev/null" "SELinux status"
check_append "AppArmor Status" "sudo aa-status 2>/dev/null" "AppArmor status"

# Summary
echo -e "${GREEN}[+] Audit complete. Results saved to $OUTPUT_FILE${NC}"

# Optional: Print critical findings to console
echo -e "\n${YELLOW}=== Critical Findings Summary ===${NC}"
grep -i -E 'warning|error|permitrootlogin yes|password.*no|world writable|suid|0:0|empty|disabled' $OUTPUT_FILE | grep -v -E 'grep|Description|Checking' | head -20

exit 0
