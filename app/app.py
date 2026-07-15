from flask import Flask, render_template, jsonify, make_response, session, redirect, url_for, request
import json
import os
from datetime import datetime
from collections import Counter
import hashlib

app = Flask(__name__)
app.secret_key = 'sentinelai-secret-2026'

# ── RBAC ─────────────────────────────────────────────────

ROLE_PERMISSIONS = {
    'Admin': {
        'can_view_dashboard':  True,  'can_view_incidents': True,
        'can_view_blocked':    True,  'can_view_activity':  True,
        'can_view_threatmap':  True,  'can_view_reports':   True,
        'can_view_settings':   True,  'can_download_report': True,
        'can_clear_incidents': True,  'can_clear_blocked':  True,
        'can_view_profile':    True,  'can_register_users': True,
    },
    'SOC Analyst': {
        'can_view_dashboard':  True,  'can_view_incidents': True,
        'can_view_blocked':    True,  'can_view_activity':  True,
        'can_view_threatmap':  True,  'can_view_reports':   True,
        'can_view_settings':   False, 'can_download_report': True,
        'can_clear_incidents': False, 'can_clear_blocked':  False,
        'can_view_profile':    True,  'can_register_users': False,
    },
    'Security Engineer': {
        'can_view_dashboard':  True,  'can_view_incidents': True,
        'can_view_blocked':    True,  'can_view_activity':  True,
        'can_view_threatmap':  True,  'can_view_reports':   True,
        'can_view_settings':   True,  'can_download_report': True,
        'can_clear_incidents': False, 'can_clear_blocked':  True,
        'can_view_profile':    True,  'can_register_users': False,
    },
    'Threat Hunter': {
        'can_view_dashboard':  True,  'can_view_incidents': True,
        'can_view_blocked':    True,  'can_view_activity':  True,
        'can_view_threatmap':  True,  'can_view_reports':   False,
        'can_view_settings':   False, 'can_download_report': False,
        'can_clear_incidents': False, 'can_clear_blocked':  False,
        'can_view_profile':    True,  'can_register_users': False,
    },
    'Incident Responder': {
        'can_view_dashboard':  True,  'can_view_incidents': True,
        'can_view_blocked':    False, 'can_view_activity':  True,
        'can_view_threatmap':  False, 'can_view_reports':   True,
        'can_view_settings':   False, 'can_download_report': True,
        'can_clear_incidents': False, 'can_clear_blocked':  False,
        'can_view_profile':    True,  'can_register_users': False,
    },
}

def get_permissions(role):
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS['Threat Hunter'])

def has_permission(permission):
    user  = session.get('user', {})
    role  = user.get('role', 'Threat Hunter')
    perms = get_permissions(role)
    return perms.get(permission, False)

def permission_denied_page(permission):
    u = session.get('user', {})
    return render_template(
        'unauthorized.html',
        user=u,
        required_permission=permission,
        perms=get_permissions(u.get('role', 'Threat Hunter'))
    )

def permission_denied_api(permission):
    return jsonify({'error': 'Permission denied', 'required': permission}), 403

INCIDENTS_FILE  = "data/incidents.json"
BLOCKED_IPS_FILE = "data/blocked_ips.json"
ACTIVITY_LOG_FILE = "data/activity_log.json"
USERS_FILE      = "data/users.json"

# ── helpers ──────────────────────────────────────────────

def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return []

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def current_user():
    return session.get('user', {})

def login_required_page():
    """For page routes – redirect to login."""
    if 'user' not in session:
        return redirect(url_for('login'))
    return None

def login_required_api():
    """For API routes – return 401 JSON."""
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401
    return None

# ── auth routes ──────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_json(USERS_FILE)
        pw_hash = hash_pw(password)
        for u in users:
            if u["username"] == username and u["password"] == pw_hash:
                session['user'] = {
                    "username":     u["username"],
                    "full_name":    u["full_name"],
                    "role":         u["role"],
                    "email":        u["email"],
                    "avatar_letter": u["avatar_letter"],
                }
                return redirect(url_for('dashboard'))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if 'user' in session:
        if not has_permission('can_register_users'):
            return permission_denied_page('can_register_users')
        return redirect(url_for('dashboard'))
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        email     = request.form.get("email", "").strip()
        role      = request.form.get("role", "SOC Analyst").strip()
        users = load_json(USERS_FILE)
        if any(u["username"] == username for u in users):
            return render_template("register.html", error="Username already taken")
        avatar_letter = full_name[0].upper() if full_name else "U"
        new_user = {
            "username":     username,
            "password":     hash_pw(password),
            "full_name":    full_name,
            "role":         role,
            "email":        email,
            "avatar_letter": avatar_letter,
        }
        users.append(new_user)
        save_json(USERS_FILE, users)
        session['user'] = {
            "username":     username,
            "full_name":    full_name,
            "role":         role,
            "email":        email,
            "avatar_letter": avatar_letter,
        }
        return redirect(url_for('dashboard'))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── page routes ──────────────────────────────────────────

@app.route("/")
def dashboard():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_dashboard'):
        return permission_denied_page('can_view_dashboard')
    u = current_user()
    return render_template("dashboard.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/incidents")
def incidents():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_incidents'):
        return permission_denied_page('can_view_incidents')
    u = current_user()
    return render_template("incidents.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/blocked")
def blocked():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_blocked'):
        return permission_denied_page('can_view_blocked')
    u = current_user()
    return render_template("blocked.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/activity")
def activity():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_activity'):
        return permission_denied_page('can_view_activity')
    u = current_user()
    return render_template("activity.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/threatmap")
def threatmap():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_threatmap'):
        return permission_denied_page('can_view_threatmap')
    u = current_user()
    return render_template("threatmap.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/settings")
def settings():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_settings'):
        return permission_denied_page('can_view_settings')
    u = current_user()
    return render_template("settings.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/reports")
def reports():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_view_reports'):
        return permission_denied_page('can_view_reports')
    u = current_user()
    return render_template("reports.html", user=u, perms=get_permissions(u.get('role', '')))

@app.route("/profile")
def profile():
    guard = login_required_page()
    if guard: return guard
    u = session.get('user', {
        'full_name': 'Admin User', 'role': 'SOC Analyst',
        'email': 'admin@sentinelai.com', 'username': 'admin',
        'avatar_letter': 'A'
    })
    return render_template('profile.html', user=u, perms=get_permissions(u.get('role', '')))

@app.route("/auth/update-profile", methods=["POST"])
def update_profile():
    guard = login_required_page()
    if guard: return guard
    name  = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    role  = request.form.get('role', '').strip()
    try:
        users = load_json(USERS_FILE)
        username = session.get('user', {}).get('username', '')
        for u in users:
            if u['username'] == username:
                u['full_name']     = name
                u['email']         = email
                u['role']          = role
                u['avatar_letter'] = name[0].upper() if name else 'A'
                break
        save_json(USERS_FILE, users)
        if 'user' in session:
            session['user']['full_name']     = name
            session['user']['email']         = email
            session['user']['role']          = role
            session['user']['avatar_letter'] = name[0].upper() if name else 'A'
            session.modified = True
    except Exception:
        pass
    return redirect('/profile?updated=1')

@app.route("/auth/change-password", methods=["POST"])
def change_password():
    guard = login_required_page()
    if guard: return guard
    current = request.form.get('current_password', '')
    new_pwd = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')
    if new_pwd != confirm:
        return redirect('/profile?pwd_error=1')
    curr_hash = hash_pw(current)
    new_hash  = hash_pw(new_pwd)
    try:
        users    = load_json(USERS_FILE)
        username = session.get('user', {}).get('username', '')
        found    = False
        for u in users:
            if u['username'] == username:
                if u['password'] != curr_hash:
                    return redirect('/profile?pwd_error=1')
                u['password'] = new_hash
                found = True
                break
        if not found:
            return redirect('/profile?pwd_error=1')
        save_json(USERS_FILE, users)
    except Exception:
        return redirect('/profile?pwd_error=1')
    return redirect('/profile?pwd_success=1')

# ── api routes ────────────────────────────────────────────

@app.route("/api/activity")
def get_activity():
    guard = login_required_api()
    if guard: return guard
    activity = load_json(ACTIVITY_LOG_FILE)
    return jsonify(activity[::-1])

@app.route("/api/incidents")
def get_incidents():
    guard = login_required_api()
    if guard: return guard
    incidents = load_json(INCIDENTS_FILE)
    return jsonify(incidents[::-1])

@app.route("/api/blocked-ips")
def get_blocked():
    guard = login_required_api()
    if guard: return guard
    blocked = load_json(BLOCKED_IPS_FILE)
    return jsonify(blocked)

@app.route("/api/clear-blocked", methods=["POST"])
def clear_blocked():
    guard = login_required_api()
    if guard: return guard
    if not has_permission('can_clear_blocked'):
        return permission_denied_api('can_clear_blocked')
    save_json(BLOCKED_IPS_FILE, [])
    return jsonify({"success": True, "message": "Blocked IPs have been reset."})

@app.route("/api/stats")
def get_stats():
    guard = login_required_api()
    if guard: return guard
    incidents = load_json(INCIDENTS_FILE)
    blocked   = load_json(BLOCKED_IPS_FILE)
    critical  = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high      = sum(1 for i in incidents if i.get("severity") == "HIGH")
    return jsonify({
        "total_incidents": len(incidents),
        "critical":        critical,
        "high":            high,
        "blocked_ips":     len(blocked)
    })

@app.route("/api/chart-data")
def get_chart_data():
    guard = login_required_api()
    if guard: return guard
    from datetime import timedelta
    incidents = load_json(INCIDENTS_FILE)
    now = datetime.now()
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    labels = []
    hours  = []
    for i in range(5, -1, -1):
        t = current_hour - timedelta(hours=i)
        hours.append(t)
        labels.append(t.strftime("%H:00"))
    critical_counts = [0] * 6
    high_counts     = [0] * 6
    for inc in incidents:
        ts_str   = inc.get("timestamp")
        severity = inc.get("severity")
        if not ts_str or severity not in ["CRITICAL", "HIGH"]:
            continue
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        inc_hour = ts.replace(minute=0, second=0, microsecond=0)
        if inc_hour in hours:
            idx = hours.index(inc_hour)
            if severity == "CRITICAL":
                critical_counts[idx] += 1
            elif severity == "HIGH":
                high_counts[idx] += 1
    return jsonify({"labels": labels, "critical": critical_counts, "high": high_counts})

@app.route("/api/clear-incidents", methods=["POST"])
def clear_incidents():
    guard = login_required_api()
    if guard: return guard
    if not has_permission('can_clear_incidents'):
        return permission_denied_api('can_clear_incidents')
    save_json(INCIDENTS_FILE,   [])
    save_json(BLOCKED_IPS_FILE, [])
    return jsonify({"status": "success"})

@app.route("/api/report-preview")
def report_preview():
    guard = login_required_api()
    if guard: return guard
    if not has_permission('can_view_reports'):
        return permission_denied_api('can_view_reports')
    incidents = load_json(INCIDENTS_FILE)
    blocked   = load_json(BLOCKED_IPS_FILE)
    critical = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high     = sum(1 for i in incidents if i.get("severity") == "HIGH")
    medium   = sum(1 for i in incidents if i.get("severity") == "MEDIUM")
    low      = sum(1 for i in incidents if i.get("severity") == "LOW")
    threat_counts = Counter(i.get("threat_type", "Unknown") for i in incidents)
    ip_counts     = Counter(i.get("ip", "Unknown") for i in incidents)
    IP_COUNTRY = {
        "45.33.32.156":   "United States",
        "103.21.244.0":   "Singapore",
        "192.168.1.105":  "India",
        "185.220.101.45": "UK",
        "91.108.4.1":     "Russia",
        "194.165.16.11":  "France",
    }
    top_ips = [
        {"ip": ip, "count": count, "country": IP_COUNTRY.get(ip, "Unknown")}
        for ip, count in ip_counts.most_common(5)
    ]
    top_threats = [
        {"type": threat, "count": count}
        for threat, count in threat_counts.most_common(10)
    ]
    recent_critical = [i for i in reversed(incidents) if i.get("severity") == "CRITICAL"][:5]
    return jsonify({
        "generated_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_incidents": len(incidents),
        "critical":        critical,
        "high":            high,
        "medium":          medium,
        "low":             low,
        "blocked_ips":     len(blocked),
        "top_threats":     top_threats,
        "top_ips":         top_ips,
        "recent_critical": recent_critical,
        "blocked_list":    blocked,
    })

@app.route("/report/download")
def download_report():
    guard = login_required_page()
    if guard: return guard
    if not has_permission('can_download_report'):
        return permission_denied_page('can_download_report')
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                    TableStyle, PageBreak, HRFlowable)
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io

    incidents = load_json(INCIDENTS_FILE)
    blocked   = load_json(BLOCKED_IPS_FILE)
    critical = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
    high     = sum(1 for i in incidents if i.get("severity") == "HIGH")
    medium   = sum(1 for i in incidents if i.get("severity") == "MEDIUM")
    low      = sum(1 for i in incidents if i.get("severity") == "LOW")
    threat_counts = Counter(i.get("threat_type", "Unknown") for i in incidents)
    ip_counts     = Counter(i.get("ip", "Unknown") for i in incidents)
    top_ips = []
    for ip, count in ip_counts.most_common(5):
        ip_threats = [i.get("threat_type", "Unknown") for i in incidents if i.get("ip") == ip]
        top_threat = Counter(ip_threats).most_common(1)[0][0] if ip_threats else "Unknown"
        top_ips.append((ip, count, top_threat))
    criticals = [i for i in reversed(incidents) if i.get("severity") == "CRITICAL"][:10]

    C_BG      = colors.HexColor("#0d1117")
    C_GREEN   = colors.HexColor("#00ff41")
    C_GREEN_DK= colors.HexColor("#008f11")
    C_RED     = colors.HexColor("#ff4444")
    C_ORANGE  = colors.HexColor("#ff9933")
    C_BLUE    = colors.HexColor("#3399ff")
    C_WHITE   = colors.HexColor("#c9d1d9")
    C_PANEL   = colors.HexColor("#161b22")
    C_RED_ROW = colors.HexColor("#2a0000")

    W, H = A4
    buf = io.BytesIO()

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.setStrokeColor(C_GREEN_DK)
        canvas.setLineWidth(1)
        canvas.rect(10, 10, W - 20, H - 20, fill=0, stroke=1)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_GREEN_DK)
        canvas.drawCentredString(W / 2, 16,
            "Page {}  |  SIEM Threat Intelligence Report  |  CONFIDENTIAL".format(doc.page))
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
        title="SIEM Threat Summary Report")

    def ps(name, font="Helvetica", size=10, color=C_WHITE,
           align=TA_LEFT, sb=0, sa=4, leading=None):
        return ParagraphStyle(name, fontName=font, fontSize=size, textColor=color,
            alignment=align, spaceBefore=sb, spaceAfter=sa,
            leading=leading or size + 4)

    s_title = ps("t", "Helvetica-Bold", 28, C_GREEN,    TA_CENTER, 60, 8)
    s_sub   = ps("s", "Helvetica",      13, C_WHITE,    TA_CENTER,  0, 6)
    s_date  = ps("d", "Helvetica",      10, C_GREEN_DK, TA_CENTER,  4, 40)
    s_hdr   = ps("h", "Helvetica-Bold", 12, C_BG,       TA_LEFT,   14, 6)
    s_body  = ps("b", "Helvetica",       9, C_WHITE)
    s_label = ps("l", "Helvetica-Bold",  9, C_GREEN)

    story = []
    story.append(Spacer(1, 60))
    story.append(Paragraph("SentinelAI Threat Intelligence Report", s_title))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="90%", thickness=2, color=C_GREEN, spaceAfter=12))
    story.append(Paragraph("Powered by Autonomous AI Agents", s_sub))
    story.append(Paragraph(
        "Generated: {}".format(datetime.now().strftime("%A, %B %d %Y  -  %H:%M:%S")), s_date))

    def stat_cell(val, lbl, col):
        return Paragraph("<b>{}</b><br/>{}".format(val, lbl),
            ps("sp_{}".format(lbl), "Helvetica-Bold", 14, col, TA_CENTER))

    stat_data = [[
        stat_cell(len(incidents), "Total Incidents", C_GREEN),
        stat_cell(critical,       "Critical",        C_RED),
        stat_cell(high,           "High",            C_ORANGE),
        stat_cell(len(blocked),   "Blocked IPs",     C_BLUE),
    ]]
    st = Table(stat_data, colWidths=[W * 0.2] * 4, rowHeights=[60])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(0,0), colors.HexColor("#002a00")),
        ("BACKGROUND", (1,0),(1,0), colors.HexColor("#2a0000")),
        ("BACKGROUND", (2,0),(2,0), colors.HexColor("#2a1500")),
        ("BACKGROUND", (3,0),(3,0), colors.HexColor("#00143d")),
        ("BOX",(0,0),(0,0),1,C_GREEN), ("BOX",(1,0),(1,0),1,C_RED),
        ("BOX",(2,0),(2,0),1,C_ORANGE),("BOX",(3,0),(3,0),1,C_BLUE),
        ("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
    ]))
    story.append(st)
    story.append(Spacer(1, 30))
    story.append(HRFlowable(width="90%", thickness=1, color=C_GREEN_DK))
    story.append(PageBreak())

    def sec_hdr(title, bg=C_GREEN):
        t = Table([[Paragraph(title, s_hdr)]], colWidths=[W - 40*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),bg),("LEFTPADDING",(0,0),(-1,-1),8),
            ("RIGHTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        return t

    def data_table(rows, col_widths, extra=None):
        t = Table(rows, colWidths=col_widths, repeatRows=1)
        base = [
            ("BACKGROUND",(0,0),(-1,0),C_GREEN_DK),("TEXTCOLOR",(0,0),(-1,0),C_BG),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),
            ("FONTNAME",(0,1),(-1,-1),"Helvetica"),("TEXTCOLOR",(0,1),(-1,-1),C_WHITE),
            ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#30363d")),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_BG,C_PANEL]),
            ("ALIGN",(0,0),(-1,-1),"LEFT"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),
            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]
        if extra:
            base.extend(extra)
        t.setStyle(TableStyle(base))
        return t

    story.append(sec_hdr("  EXECUTIVE SUMMARY"))
    story.append(Spacer(1, 4))
    exec_rows = [
        [Paragraph("Severity",s_label),Paragraph("Count",s_label)],
        [Paragraph("Total Incidents",s_body),Paragraph(str(len(incidents)),s_body)],
        [Paragraph("CRITICAL",s_body),Paragraph(str(critical),s_body)],
        [Paragraph("HIGH",s_body),Paragraph(str(high),s_body)],
        [Paragraph("MEDIUM",s_body),Paragraph(str(medium),s_body)],
        [Paragraph("LOW",s_body),Paragraph(str(low),s_body)],
        [Paragraph("Blocked IPs",s_body),Paragraph(str(len(blocked)),s_body)],
    ]
    story.append(data_table(exec_rows,[100,60],[
        ("BACKGROUND",(0,2),(1,2),colors.HexColor("#2a0000")),("TEXTCOLOR",(0,2),(1,2),C_RED),
        ("BACKGROUND",(0,3),(1,3),colors.HexColor("#2a1500")),("TEXTCOLOR",(0,3),(1,3),C_ORANGE),
    ]))
    story.append(Spacer(1, 14))
    story.append(sec_hdr("  TOP THREAT TYPES"))
    story.append(Spacer(1, 4))
    if threat_counts:
        max_c = max(threat_counts.values())
        th_rows = [[Paragraph("Threat Type",s_label),Paragraph("Count",s_label),Paragraph("Frequency",s_label)]]
        for threat, count in threat_counts.most_common():
            bar = "\u2588" * int((count/max_c)*28)
            th_rows.append([Paragraph(threat,s_body),Paragraph(str(count),s_body),
                            Paragraph('<font color="#00ff41">{}</font>'.format(bar),s_body)])
        story.append(data_table(th_rows,[130,50,150]))
    else:
        story.append(Paragraph("No threat data available.",s_body))
    story.append(Spacer(1, 14))
    story.append(sec_hdr("  TOP ATTACKER IPs"))
    story.append(Spacer(1, 4))
    if top_ips:
        ip_rows = [[Paragraph("IP Address",s_label),Paragraph("Incidents",s_label),Paragraph("Primary Threat",s_label)]]
        for ip, count, threat in top_ips:
            ip_rows.append([Paragraph(ip,s_body),Paragraph(str(count),s_body),Paragraph(threat,s_body)])
        story.append(data_table(ip_rows,[120,60,150]))
    else:
        story.append(Paragraph("No attacker IP data available.",s_body))
    story.append(PageBreak())
    story.append(sec_hdr("  BLOCKED IP ADDRESSES",bg=C_RED))
    story.append(Spacer(1, 4))
    if blocked:
        cols = 4
        padded = blocked + [""] * ((cols - len(blocked)%cols)%cols)
        grid_rows = [
            [Paragraph(cell,ps("bip{}".format(idx),"Helvetica",8,C_RED,TA_CENTER))
             for cell in padded[i:i+cols]]
            for idx,i in enumerate(range(0,len(padded),cols))
        ]
        g = Table(grid_rows,colWidths=[(W-40*mm)/cols]*cols)
        g.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#1a0000")),
            ("BOX",(0,0),(-1,-1),0.5,C_RED),
            ("INNERGRID",(0,0),(-1,-1),0.5,colors.HexColor("#3d0000")),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ]))
        story.append(g)
    else:
        story.append(Paragraph("No IPs currently blocked.",s_body))
    story.append(Spacer(1, 14))
    story.append(sec_hdr("  RECENT CRITICAL INCIDENTS (Last 10)",bg=C_RED))
    story.append(Spacer(1, 4))
    if criticals:
        cw = (W-40*mm)/6
        inc_rows = [[Paragraph(h,s_label) for h in ["ID","Timestamp","Threat","IP","Action","Reason"]]]
        for inc in criticals:
            inc_rows.append([
                Paragraph(str(inc.get("id","-")),s_body),
                Paragraph(str(inc.get("timestamp","-")),s_body),
                Paragraph(str(inc.get("threat_type","-")),s_body),
                Paragraph(str(inc.get("ip","-")),s_body),
                Paragraph(str(inc.get("action_taken","-")),s_body),
                Paragraph(str(inc.get("reason","-")),s_body),
            ])
        story.append(data_table(inc_rows,[cw]*6,[
            ("BACKGROUND",(0,1),(-1,-1),C_RED_ROW),("TEXTCOLOR",(0,1),(-1,-1),C_RED),
        ]))
    else:
        story.append(Paragraph("No critical incidents recorded.",s_body))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    buf.seek(0)
    response = make_response(buf.read())
    response.headers["Content-Disposition"] = "attachment; filename=siem_report.pdf"
    response.headers["Content-Type"] = "application/pdf"
    return response

@app.route("/api/permissions")
def api_permissions():
    guard = login_required_api()
    if guard: return guard
    u    = session.get('user', {})
    role = u.get('role', 'Threat Hunter')
    return jsonify({
        "role":        role,
        "permissions": get_permissions(role)
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
