import json
import os
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS_FILE = os.path.join(BASE_DIR, "data", "incidents.json")
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "data", "blocked_ips.json")
ACTIVITY_LOG_FILE = os.path.join(BASE_DIR, "data", "activity_log.json")

def log_activity(agent, action, detail=""):
    try:
        if os.path.exists(ACTIVITY_LOG_FILE):
            with open(ACTIVITY_LOG_FILE, "r") as f:
                logs = json.load(f)
        else:
            logs = []
        logs.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "agent": agent,
            "action": action,
            "detail": detail
        })
        logs = logs[-50:]
        with open(ACTIVITY_LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except:
        pass

def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return []

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def send_email_alert(incident):
    try:
        sender_email = os.getenv("ALERT_EMAIL")
        sender_password = os.getenv("ALERT_PASSWORD")
        receiver_email = os.getenv("ALERT_RECEIVER")
        
        if not sender_email or not sender_password or not receiver_email:
            print("Email failed: Missing credentials in .env")
            return
            
        subject = "CRITICAL THREAT DETECTED — " + str(incident.get("id", ""))
        
        body = f"Incident ID: {incident.get('id', '')}\n" \
               f"Timestamp: {incident.get('timestamp', '')}\n" \
               f"Threat Type: {incident.get('threat_type', '')}\n" \
               f"IP Address: {incident.get('ip', '')}\n" \
               f"Action Taken: {incident.get('action_taken', '')}\n" \
               f"Reason: {incident.get('reason', '')}"

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = receiver_email

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("Email alert sent!")
    except Exception as e:
        print("Email failed: " + str(e))

def extract_ip(log_line):
    """Extract IP address from log line"""
    import re
    match = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', log_line)
    return match.group(1) if match else "Unknown"

def respond(log_line, analysis):
    """
    Takes action based on AI analysis.
    """
    threat_type = analysis.get('threat_type', 'Unknown') if analysis else 'Unknown'
    log_activity("Responder Agent", "Received analysis", "Threat: " + threat_type)
    if not analysis or not analysis.get("is_threat"):
        log_activity("Responder Agent", "No threat", "Marked as SAFE")
        print(f"✅ SAFE — {log_line[:60]}...")
        return

    severity   = analysis.get("severity", "LOW")
    threat     = analysis.get("threat_type", "Unknown")
    action     = analysis.get("recommended_action", "Monitor")
    reason     = analysis.get("reason", "")
    ip         = extract_ip(log_line)
    timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Print colored alert to terminal
    if severity == "CRITICAL":
        print(f"\n🚨 CRITICAL THREAT DETECTED!")
    elif severity == "HIGH":
        print(f"\n⚠️  HIGH SEVERITY THREAT!")
    else:
        print(f"\n⚡ THREAT DETECTED ({severity})")

    print(f"   Type     : {threat}")
    print(f"   IP       : {ip}")
    print(f"   Action   : {action}")
    print(f"   Reason   : {reason}")

    # Load existing data
    incidents  = load_json(INCIDENTS_FILE)
    blocked    = load_json(BLOCKED_IPS_FILE)

    # Create incident record
    incident = {
        "id"          : f"INC-{str(len(incidents)+1).zfill(3)}",
        "timestamp"   : timestamp,
        "log_entry"   : log_line,
        "threat_type" : threat,
        "severity"    : severity,
        "action_taken": action,
        "ip"          : ip,
        "reason"      : reason
    }
    incidents.append(incident)
    save_json(INCIDENTS_FILE, incidents)
    print(f"   📁 Incident saved: {incident['id']}")

    log_activity("Responder Agent", "Incident saved", str(incident['id']) + " — " + str(threat) + " from " + str(ip))

    if severity == "CRITICAL":
        send_email_alert(incident)

    # Block IP if HIGH or CRITICAL
    if severity in ["HIGH", "CRITICAL"] and ip not in blocked and ip != "Unknown":
        blocked.append(ip)
        save_json(BLOCKED_IPS_FILE, blocked)
        print(f"   🚫 IP BLOCKED: {ip}")
        log_activity("Responder Agent", "IP BLOCKED", ip)

if __name__ == "__main__":
    # Test responder with a fake analysis
    test_log = "[2026-07-05 22:09:51] CRITICAL | DDoS pattern detected | IP: 192.168.1.105 | Requests: 375/second"
    test_analysis = {
        "is_threat": True,
        "threat_type": "DDoS",
        "severity": "CRITICAL",
        "recommended_action": "Block IP",
        "reason": "Extremely high request rate indicates DDoS attack"
    }
    respond(test_log, test_analysis)
    print("\n✅ Check data/incidents.json and data/blocked_ips.json")