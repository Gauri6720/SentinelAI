import random
import time
from datetime import datetime

# Fake IPs — some are "attackers"
ATTACKER_IPS = [
    "45.33.32.156", "103.21.244.0", "192.168.1.105",
    "185.220.101.45", "91.108.4.1", "194.165.16.11"
]
NORMAL_IPS = [
    "203.0.113.42", "198.51.100.5", "192.0.2.88",
    "172.16.254.1", "10.0.0.25"
]

# Log templates
ATTACK_LOGS = [
    ("CRITICAL", "Brute force attack detected | {ip} made 50 failed login attempts in 60 seconds"),
    ("ERROR",    "SQL Injection attempt detected | IP: {ip} | Path: /login?id=1' OR '1'='1"),
    ("ERROR",    "Port scan detected | IP: {ip} | Scanned ports: 22,80,443,3306,8080"),
    ("WARNING",  "Failed SSH login | IP: {ip} | Username: root | Attempt: {n}"),
    ("CRITICAL", "Directory traversal attack | IP: {ip} | Path: /../../../etc/passwd"),
    ("ERROR",    "XSS attack attempt | IP: {ip} | Payload: <script>alert('xss')</script>"),
    ("WARNING",  "Multiple failed login attempts | IP: {ip} | Count: {n}"),
    ("CRITICAL", "DDoS pattern detected | IP: {ip} | Requests: {n}/second"),
]

NORMAL_LOGS = [
    ("INFO", "GET /home | IP: {ip} | Status: 200 | Response: 45ms"),
    ("INFO", "GET /about | IP: {ip} | Status: 200 | Response: 30ms"),
    ("INFO", "POST /contact | IP: {ip} | Status: 200 | Response: 60ms"),
    ("INFO", "User login successful | IP: {ip} | Status: 200"),
]

def generate_log():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 60% chance attack, 40% chance normal
    if random.random() < 0.6:
        ip = random.choice(ATTACKER_IPS)
        level, template = random.choice(ATTACK_LOGS)
    else:
        ip = random.choice(NORMAL_IPS)
        level, template = random.choice(NORMAL_LOGS)

    message = template.format(ip=ip, n=random.randint(10, 999))
    log_line = f"[{timestamp}] {level:<8} | {message}\n"
    return log_line

def run():
    log_path = "logs/system.log"
    print("🚀 Log Generator started — writing to logs/system.log")
    print("Press Ctrl+C to stop\n")

    while True:
        log_line = generate_log()
        with open(log_path, "a") as f:
            f.write(log_line)
        print(log_line.strip())
        time.sleep(2)  # new log every 2 seconds

if __name__ == "__main__":
    run()