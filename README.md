## Linux Security Audit Tool

### Overview

**Linux-Audit-Tool** is an automated Bash script for comprehensive Linux security auditing, developed by Moksh Sharma. The script is designed to quickly gather, organize, and report on a wide array of security-relevant system settings, user configurations, network exposures, and auditing frameworks. It produces a detailed plaintext report that can be used by system administrators and security professionals to identify and remediate common security issues.

### Key Features

- **User Account and Password Policy Audit**  
  Lists all users, checks for empty or weak passwords, highlights accounts with UID 0 (root), and reports on login histories and password aging policies.

- **SSH Configuration Check**  
  Audits SSH settings for protocol version, root login permissions, and general security configuration.

- **Network and Firewall Review**  
  Enumerates active network connections, running services, open ports, firewall (iptables/UFW) status, routing, and ARP tables.

- **System Services and Permissions**  
  Reports on running/enabled services, open files, world-writable/SUID/SGID/unowned files, and critical system file permissions.

- **Kernel and System Hardening**  
  Captures kernel parameters, ASLR, and core dump settings for review.

- **Logging and Auditing**  
  Checks audit status, current audit rules, and recent authentication logs.

- **Package and Update Status**  
  Lists all installed packages and checks for available security updates (supports both apt and yum/rpm).

- **Cron Jobs Enumeration**  
  Gathers and displays both system and user cron jobs and their contents.

- **Mandatory Access Control**  
  Reviews SELinux and AppArmor status (if present).

- **Critical Findings Highlight**  
  Summarizes potential security issues at the end of the script run.

### Usage

This script is designed for administrative users and should be run with `sudo` or root privileges for comprehensive results. Output is saved as a timestamped report in your current working directory.

### Disclaimer

**Always review the results and commands before remediation. This tool is for auditing and assessment purposes only and does not make any system changes.**

## Releases Will Be Uploaded Regularly 
