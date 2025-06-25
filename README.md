# 🔐 Failed Login Detection Using Log Analysis

This project analyzes Linux system logs to detect failed login attempts. It helps identify brute-force attacks or unauthorized access attempts by scanning `/var/log/auth.log`.

## 🚀 Features
- Parses system authentication logs
- Detects failed login attempts
- Extracts suspicious IP addresses
- Displays number of failed attempts per IP

## 📂 Log File Format Example
Jun 25 08:34:12 ubuntu sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54422 ssh2

## 🛠 How to Run

### 🐍 Using Python (Linux system):
1. Open terminal
2. Run the script with root privileges:
```bash
sudo python3 detect_failed_logins.py
Suspicious IPs with failed login attempts:
192.168.1.100 — 7 failed attempts
10.0.2.5 — 3 failed attempts
