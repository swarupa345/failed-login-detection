
---

## ✅ 2. `detect_failed_logins.py` – Python Script

Create a file `detect_failed_logins.py` and paste this:

```python
#!/usr/bin/env python3

import re
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"  # Change if you're using CentOS (/var/log/secure)

# Regex pattern to match failed login lines
FAILED_LOGIN_PATTERN = re.compile(r"Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)")

def parse_log():
    failed_ips = defaultdict(int)

    try:
        with open(LOG_FILE, "r") as log_file:
            for line in log_file:
                match = FAILED_LOGIN_PATTERN.search(line)
                if match:
                    ip = match.group(1)
                    failed_ips[ip] += 1
    except FileNotFoundError:
        print(f"Log file not found: {LOG_FILE}")
        return

    if failed_ips:
        print("\n🚨 Suspicious IPs with failed login attempts:")
        for ip, count in failed_ips.items():
            print(f"{ip} — {count} failed attempts")
    else:
        print("✅ No failed login attempts detected.")

if __name__ == "__main__":
    parse_log()
