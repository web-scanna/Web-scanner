# database.py - SQLite helper with JSON issue storage
import sqlite3
import json
from datetime import datetime

DB = "scans.db"

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        status_code INTEGER,
        issues TEXT NOT NULL DEFAULT '[]'
      )
    """)
    conn.commit()
    conn.close()

def save_scan(url, issues, score, status_code=None):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute(
        "INSERT INTO scans (url, timestamp, score, status_code, issues) VALUES (?, ?, ?, ?, ?)",
        (url, timestamp, score, status_code, json.dumps(issues))
    )
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_history():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, timestamp, url, score, status_code, issues FROM scans ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    results = []
    for row in rows:
        scan_id, timestamp, url, score, status_code, issues_json = row
        try:
            issues = json.loads(issues_json)
        except Exception:
            issues = []
        results.append({
            "id": scan_id,
            "timestamp": timestamp,
            "url": url,
            "score": score,
            "status_code": status_code,
            "issues": issues,
            "issue_count": len(issues),
        })
    return results

def get_scan(scan_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, timestamp, url, score, status_code, issues FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    scan_id, timestamp, url, score, status_code, issues_json = row
    try:
        issues = json.loads(issues_json)
    except Exception:
        issues = []
    return {
        "id": scan_id,
        "timestamp": timestamp,
        "url": url,
        "score": score,
        "status_code": status_code,
        "issues": issues,
        "issue_count": len(issues),
    }

def get_stats():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT issues, score FROM scans ORDER BY id DESC LIMIT 500")
    rows = c.fetchall()
    conn.close()

    category_counts = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    title_counts = {}
    scores = []

    for issues_json, score in rows:
        scores.append(score)
        try:
            issues = json.loads(issues_json)
        except Exception:
            continue
        for issue in issues:
            cat = issue.get("category", "other")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            sev = issue.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            title = issue.get("title", "")
            title_counts[title] = title_counts.get(title, 0) + 1

    avg_score = round(sum(scores) / len(scores)) if scores else 0
    top_issues = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_scans": len(rows),
        "avg_score": avg_score,
        "category_counts": category_counts,
        "severity_counts": severity_counts,
        "top_issues": [{"title": t, "count": c} for t, c in top_issues],
    }
