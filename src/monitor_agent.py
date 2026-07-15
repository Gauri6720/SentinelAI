import time
import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

def monitor(log_path="logs/system.log", callback=None):
    """
    Watches log file for new lines.
    Calls callback(line) for every new line found.
    """
    print(f"👁️  Monitor Agent watching: {log_path}")

    # Create log file if it doesn't exist
    if not os.path.exists(log_path):
        open(log_path, "w").close()

    # Start reading from the end of file
    with open(log_path, "r") as f:
        f.seek(0, 2)  # go to end of file

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:  # skip empty lines
                    log_activity("Monitor Agent", "New log detected", line[:60])
                    print(f"📥 New log: {line}")
                    if callback:
                        callback(line)
            else:
                time.sleep(1)  # wait 1 second and check again

if __name__ == "__main__":
    # Test monitor alone — just prints new lines
    def test_callback(line):
        print(f"✅ Monitor received: {line[:60]}...")

    monitor(callback=test_callback)