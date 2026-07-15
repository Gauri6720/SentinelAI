import os
import json
from groq import Groq
from dotenv import load_dotenv
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

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze_log(log_line):
    log_activity("Analyst Agent", "Analyzing log", log_line[:60])
    """
    Sends a log line to Groq AI.
    Returns structured threat analysis.
    """
    prompt = f"""You are a cybersecurity analyst AI. Analyze this server log entry and respond ONLY in valid JSON format. No explanation, no extra text, just JSON.

Log entry: {log_line}

Respond with exactly this JSON structure:
{{
    "is_threat": true or false,
    "threat_type": "e.g. Brute Force / SQL Injection / Port Scan / DDoS / Directory Traversal / XSS / None",
    "severity": "LOW or MEDIUM or HIGH or CRITICAL",
    "recommended_action": "e.g. Block IP / Monitor / Ignore",
    "reason": "one short sentence explaining why"
}}"""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.1  # low temperature = consistent responses
        )

        raw = response.choices[0].message.content.strip()

        # Clean up response in case AI adds extra text
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()

        result = json.loads(raw)
        
        log_activity("Analyst Agent", "Analysis complete", 
                     f"Threat: {result.get('threat_type', 'Unknown')} | Severity: {result.get('severity', 'Unknown')}")
                     
        return result

    except json.JSONDecodeError:
        # If AI response isn't valid JSON, return safe default  
        log_activity("Analyst Agent", "Invalid JSON response", "Returning safe default")
        return {
            "is_threat": False,
            "threat_type": "Unknown",
            "severity": "LOW",
            "recommended_action": "Monitor",
            "reason": "Could not parse AI"
        }
    except Exception as e:
        print(f"❌ Analyst error: {e}")
        return None

if __name__ == "__main__":
    # Test with sample logs
    test_logs = [
        "[2026-07-05 22:09:51] CRITICAL | DDoS pattern detected | IP: 192.168.1.105 | Requests: 375/second",
        "[2026-07-05 22:09:43] INFO     | User login successful | IP: 192.0.2.88 | Status: 200",
        "[2026-07-05 22:09:39] ERROR    | SQL Injection attempt | IP: 45.33.32.156 | Path: /login?id=1' OR '1'='1",
    ]

    for log in test_logs:
        print(f"\n📋 Log: {log[:70]}...")
        result = analyze_log(log)
        print(f"🤖 Analysis: {json.dumps(result, indent=2)}")
        print("-" * 50)