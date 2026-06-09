from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import hashlib
import os
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = "scamshield-secret-key-2025-india"  # Change this in production

DB = "users.db"


def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT    NOT NULL,
            email     TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            role      TEXT    DEFAULT 'Job Seeker',
            created   TEXT    NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            job_text  TEXT,
            score     INTEGER,
            verdict   TEXT,
            created   TEXT
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user_by_email(email):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = c.fetchone()
    conn.close()
    return row

def create_user(name, email, password, role):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO users (name, email, password, role, created) VALUES (?, ?, ?, ?, ?)",
            (name, email.lower(), hash_password(password), role, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Email already exists
    finally:
        conn.close()

def save_scan(user_id, job_text, score, verdict):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (user_id, job_text, score, verdict, created) VALUES (?, ?, ?, ?, ?)",
        (user_id, job_text[:500], score, verdict, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_user_stats(user_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE user_id = ? AND verdict = 'high'", (user_id,))
    flagged = c.fetchone()[0]
    conn.close()
    return {"total": total, "flagged": flagged, "safe": total - flagged}


SCAM_PATTERNS = [
    {
        "keys": ["registration fee", "processing fee", "pay to apply",
                 "payment required", "starter kit", "equipment fee",
                 "security deposit", "training fee"],
        "label": "💰 Payment Red Flag",
        "weight": 35
    },
    {
        "keys": ["aadhar", "aadhaar", "pan card", "bank account",
                 "send otp", "passport copy", "national id",
                 "bank details", "credit card"],
        "label": "🪪 Personal Info Request",
        "weight": 30
    },
    {
        "keys": ["earn ₹", "guaranteed income", "unlimited earning",
                 "get rich", "financial freedom", "make money fast",
                 "earn thousands", "lakh per month", "crore salary"],
        "label": "📈 Unrealistic Claims",
        "weight": 25
    },
    {
        "keys": ["whatsapp only", "telegram", "gmail.com",
                 "yahoo.com", "hotmail.com", "personal email"],
        "label": "📱 Suspicious Contact",
        "weight": 20
    },
    {
        "keys": ["urgent hiring", "act now", "limited slots",
                 "respond within 24", "don't miss", "last chance",
                 "apply immediately"],
        "label": "⏰ Urgency Pressure",
        "weight": 15
    },
    {
        "keys": ["no experience needed", "no skills required",
                 "no degree needed", "anyone can apply",
                 "no qualification"],
        "label": "⚠️ No Requirements",
        "weight": 10
    },
    {
        "keys": ["linkedin", "official website", "careers page",
                 "hr@", "provident fund", "health insurance",
                 "structured interview", "glassdoor"],
        "label": "✅ Legitimacy Signals",
        "weight": -20
    },
]

def analyze_job(text):
    t = text.lower()
    score = 0
    signals = []

    for p in SCAM_PATTERNS:
        found = [k for k in p["keys"] if k in t]
        if found:
            contribution = abs(p["weight"]) * len(found)
            if p["weight"] < 0:
                score -= min(contribution, abs(p["weight"]) * 2)
            else:
                score += min(contribution, p["weight"] * 2)
            signals.append({
                "label":    p["label"],
                "pct":      min(100, abs(p["weight"]) * len(found)),
                "positive": p["weight"] < 0,
                "matches":  found[:2]
            })

    score = max(0, min(100, round(score)))
    level = "high" if score >= 65 else "medium" if score >= 35 else "low"

    tips = []
    for s in signals:
        if "Payment"    in s["label"]: tips.append("Never pay any fee to get hired. Legitimate employers do NOT charge money.")
        if "Personal"   in s["label"]: tips.append("Do not share Aadhaar, PAN, or bank details until you have a verified offer letter.")
        if "Unrealistic"in s["label"]: tips.append("Research industry salary standards. Extraordinary claims need extraordinary proof.")
        if "Suspicious" in s["label"]: tips.append("Only communicate through official company email domains, not Gmail/Yahoo.")
        if "Urgency"    in s["label"]: tips.append("Pressure tactics are manipulation. Take time to verify before responding.")
    if level in ["high", "medium"]:
        tips.append("Report this job to cybercrime.gov.in or the platform where you found it.")

    return {
        "score":   score,
        "level":   level,
        "signals": signals,
        "tips":    list(dict.fromkeys(tips))[:3]
    }



@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login")
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html",
        user_name  = session.get("user_name"),
        user_email = session.get("user_email"),
        user_role  = session.get("user_role")
    )



@app.route("/api/register", methods=["POST"])
def api_register():
    data     = request.get_json()
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "Job Seeker").strip()

    # Validation
    if not name:
        return jsonify({"ok": False, "error": "Please enter your full name."}), 400
    if not email or "@" not in email or "." not in email:
        return jsonify({"ok": False, "error": "Please enter a valid email address."}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters."}), 400

    ok = create_user(name, email, password, role)
    if not ok:
        return jsonify({"ok": False, "error": "This email is already registered. Please sign in."}), 400

    
    user = get_user_by_email(email)
    session["user_id"]    = user[0]
    session["user_name"]  = user[1]
    session["user_email"] = user[2]
    session["user_role"]  = user[4]
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json()
    email    = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"ok": False, "error": "Please fill in both fields."}), 400

    user = get_user_by_email(email)

    if not user:
        return jsonify({"ok": False, "error": "No account found with this email. Please register first."}), 401

    if user[3] != hash_password(password):
        return jsonify({"ok": False, "error": "Incorrect password. Please try again."}), 401

    session["user_id"]    = user[0]
    session["user_name"]  = user[1]
    session["user_email"] = user[2]
    session["user_role"]  = user[4]
    return jsonify({"ok": True})

@app.route("/api/logout")
def api_logout():
    session.clear()
    return redirect(url_for("login"))



@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Not logged in"}), 401

    data = request.get_json()
    text = data.get("text", "").strip()

    if not text:
        return jsonify({"ok": False, "error": "Please paste a job description."}), 400
    if len(text.split()) < 8:
        return jsonify({"ok": False, "error": "Text too short. Paste the full job description."}), 400

    result = analyze_job(text)
    save_scan(session["user_id"], text, result["score"], result["level"])
    return jsonify({"ok": True, **result})

@app.route("/api/stats")
def api_stats():
    if "user_id" not in session:
        return jsonify({}), 401
    stats = get_user_stats(session["user_id"])
    return jsonify(stats)

@app.route("/api/update-profile", methods=["POST"])
def api_update_profile():
    if "user_id" not in session:
        return jsonify({"ok": False}), 401
    data = request.get_json()
    name = data.get("name", "").strip()
    role = data.get("role", "").strip()
    if name:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("UPDATE users SET name=?, role=? WHERE id=?", (name, role, session["user_id"]))
        conn.commit()
        conn.close()
        session["user_name"] = name
        session["user_role"] = role
    return jsonify({"ok": True})

@app.route("/api/change-password", methods=["POST"])
def api_change_password():
    if "user_id" not in session:
        return jsonify({"ok": False}), 401
    data        = request.get_json()
    current     = data.get("current", "")
    new_pass    = data.get("new", "")
    user        = get_user_by_email(session["user_email"])
    if user[3] != hash_password(current):
        return jsonify({"ok": False, "error": "Current password is incorrect."}), 400
    if len(new_pass) < 6:
        return jsonify({"ok": False, "error": "New password must be at least 6 characters."}), 400
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE id=?", (hash_password(new_pass), session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route('/google3033f3f735ead4eb.html')
def google_verify():
    return 'google-site-verification: google3033f3f735ead4eb.html'


if __name__ == "__main__":
    init_db()
    print("\n" + "="*50)
    print("  🛡️  ScamShield AI is RUNNING!")
    print("  👉  Open:  http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)