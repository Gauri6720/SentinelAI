# import time
# import os
from monitor_agent import monitor
from analyst_agent import analyze_log
from responder_agent import respond

def process_log(log_line):
    """
    Called automatically for every new log line.
    Runs analyst → responder pipeline.
    """
    print(f"\n{'='*60}")
    print(f"📥 NEW LOG: {log_line[:70]}...")

    # Step 1 — Analyst Agent analyzes the log
    print("🧠 Analyst Agent thinking...")
    analysis = analyze_log(log_line)

    if analysis is None:
        print("❌ Analyst failed — skipping this log")
        return

    # Step 2 — Responder Agent takes action
    respond(log_line, analysis)
    print(f"{'='*60}")

def run():
    print("="*60)
    print("🛡️  SentinelAI — Autonomous Threat Detection System")
    print("="*60)
    print("📌 Monitoring: logs/system.log")
    print("📌 Incidents : data/incidents.json")
    print("📌 Blocked   : data/blocked_ips.json")
    print("Press Ctrl+C to stop\n")

    # Start monitoring — calls process_log for every new line
    monitor(callback=process_log)

if __name__ == "__main__":
    run()