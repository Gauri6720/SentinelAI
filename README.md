# 🛡️ SentinelAI — Security Operations Center

An autonomous AI-powered SIEM (Security Information and Event Management) system built with Python and Flask. SentinelAI uses multi-agent AI to monitor logs, analyse threats, and respond automatically to security incidents.

---

## Features

- **Real-time threat monitoring** — live dashboard with Leaflet.js threat map
- **AI analyst agent** — powered by Groq LLM (llama-3.3-70b-versatile)
- **Incident management** — automatic detection, classification, and response
- **Role-based access control (RBAC)** — five roles with fine-grained permissions
- **PDF report generation** — downloadable threat intelligence reports
- **Authentication system** — login, register, profile management

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.x, Flask |
| AI | Groq API (llama-3.3-70b-versatile) |
| Frontend | HTML, CSS, Vanilla JavaScript |
| Charts | Chart.js, Leaflet.js |
| Data | JSON flat-file storage |

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/your-username/sentinelai.git
cd sentinelai
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example file and fill in your real values:

```bash
cp .env.example .env
```

Open `.env` and set the following:

```env
SECRET_KEY=your_secret_key_here
GROQ_API_KEY=your_groq_api_key_here
```

#### `SECRET_KEY`
Used by Flask to sign session cookies. Must be a long, random, unpredictable string.

Generate a strong key with:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output as the value of `SECRET_KEY` in your `.env` file.

> ⚠️ **Never use a short or guessable key in production.** Anyone who knows the secret key can forge session cookies.

#### `GROQ_API_KEY`
Required by the AI analyst agent to call the Groq language model.

1. Go to [https://console.groq.com/keys](https://console.groq.com/keys)
2. Create a new API key
3. Paste it as the value of `GROQ_API_KEY` in your `.env` file

> The `.env` file is listed in `.gitignore` and will **never** be committed to the repository.

### 5. Run the application

```bash
cd app
python app.py
```

The dashboard will be available at [http://localhost:5000](http://localhost:5000).

**Default credentials:**
- Username: `admin`
- Password: `admin123`

> Change the default password immediately after first login via the Profile page.

### 6. Run the agent system (optional)

In a separate terminal:

```bash
cd src
python main.py
```

---

## Project Structure

```
sentinelai/
├── app/
│   ├── app.py              # Flask application & routes
│   └── templates/          # Jinja2 HTML templates
├── src/
│   ├── main.py             # Agent orchestrator
│   ├── monitor_agent.py    # Log monitoring agent
│   ├── analyst_agent.py    # AI threat analysis agent
│   └── responder_agent.py  # Automated response agent
├── data/
│   ├── incidents.json      # Detected incidents
│   ├── blocked_ips.json    # Blocked IP addresses
│   ├── activity_log.json   # Agent activity log
│   └── users.json          # User accounts
├── logs/
│   └── system.log          # System logs
├── .env                    # ← create this (not committed)
├── .env.example            # Template for .env
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | **Yes** | Flask session signing key |
| `GROQ_API_KEY` | **Yes** | Groq LLM API key for the analyst agent |
| `ALERT_EMAIL` | No | Email address for outbound alert emails |
| `ALERT_PASSWORD` | No | App password for the alert email account |
| `ALERT_RECEIVER` | No | Recipient address for alert emails |

---

## Roles & Permissions

| Permission | Admin | SOC Analyst | Security Engineer | Threat Hunter | Incident Responder |
|-----------|:-----:|:-----------:|:-----------------:|:-------------:|:-----------------:|
| Dashboard | ✅ | ✅ | ✅ | ✅ | ✅ |
| Incidents | ✅ | ✅ | ✅ | ✅ | ✅ |
| Blocked IPs | ✅ | ✅ | ✅ | ✅ | ❌ |
| Activity Log | ✅ | ✅ | ✅ | ✅ | ✅ |
| Threat Map | ✅ | ✅ | ✅ | ✅ | ❌ |
| Reports | ✅ | ✅ | ✅ | ❌ | ✅ |
| Settings | ✅ | ❌ | ✅ | ❌ | ❌ |
| Clear Incidents | ✅ | ❌ | ❌ | ❌ | ❌ |
| Clear Blocked IPs | ✅ | ❌ | ✅ | ❌ | ❌ |
| Register Users | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## Security Notes

- The real `.env` file is excluded from version control via `.gitignore`
- Passwords are hashed with SHA-256 before storage
- All routes are protected by login and RBAC permission checks
- Session cookies are signed with the `SECRET_KEY`
- For production, use a WSGI server (Gunicorn/uWSGI) behind a reverse proxy (Nginx)

---
