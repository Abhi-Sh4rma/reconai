import requests
import json
from backend.database.db import get_connection

GROQ_API = "https://api.groq.com/openai/v1/chat/completions"

def generate_report(scan_id, api_key):
    print(f"\n🤖 Starting AI Report Generation...")

    findings = fetch_findings(scan_id)
    prompt = build_prompt(findings)

    print(f"  → Sending findings to Groq AI...")

    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }

        payload = {
            "model": "llama-3.3-70b-versatile",
            "max_tokens": 4000,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior penetration tester who writes professional security assessment reports."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        r = requests.post(GROQ_API, headers=headers, json=payload, timeout=60)
        data = r.json()

        if "choices" in data:
            report_text = data["choices"][0]["message"]["content"]
            print(f"  ✅ AI Report generated successfully!")
            save_report(scan_id, report_text)
            return report_text
        else:
            print(f"  ❌ API Error: {data}")
            return None

    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None


def fetch_findings(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = dict(cursor.fetchone())

    cursor.execute("SELECT * FROM subdomains WHERE scan_id = ?", (scan_id,))
    subdomains = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM ports WHERE scan_id = ?", (scan_id,))
    ports = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
    vulns = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "scan": scan,
        "subdomains": subdomains,
        "ports": ports,
        "vulnerabilities": vulns
    }


def build_prompt(findings):
    domain = findings["scan"]["domain"]
    subdomains = findings["subdomains"]
    ports = findings["ports"]
    vulns = findings["vulnerabilities"]

    critical = [v for v in vulns if v["severity"] == "CRITICAL"]
    high = [v for v in vulns if v["severity"] == "HIGH"]
    medium = [v for v in vulns if v["severity"] == "Medium"]
    info = [v for v in vulns if v["severity"] in ["Info", "Unknown"]]

    prompt = f"""Generate a professional penetration testing report for:

TARGET: {domain}

SUBDOMAINS FOUND:
{json.dumps(subdomains, indent=2)}

OPEN PORTS:
{json.dumps(ports, indent=2)}

VULNERABILITIES SUMMARY:
- Critical: {len(critical)}
- High: {len(high)}
- Medium: {len(medium)}
- Informational: {len(info)}

DETAILED FINDINGS:
{json.dumps(vulns, indent=2)}

Write a professional penetration testing report with:
1. Executive Summary
2. Scope & Methodology
3. Risk Summary Table
4. Detailed Findings (description, risk, evidence, recommendation for each)
5. Conclusion & Remediation Priority

Be professional, concise and include specific remediation steps."""

    return prompt


def save_report(scan_id, report_text):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            report_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute(
        "INSERT INTO reports (scan_id, report_text) VALUES (?, ?)",
        (scan_id, report_text)
    )
    conn.commit()
    conn.close()
