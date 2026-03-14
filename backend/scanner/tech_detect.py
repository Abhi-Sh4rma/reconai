import httpx
from bs4 import BeautifulSoup
from backend.database.db import get_connection

def detect_technologies(scan_id, hosts):
    print(f"\n🔎 Starting Tech Fingerprinting for {len(hosts)} host(s)...")
    all_results = []

    for host in hosts:
        print(f"\n  → Fingerprinting: {host}")
        result = {
            "host": host,
            "technologies": [],
            "headers": {},
            "cms": None,
            "frameworks": [],
            "server": None
        }

        for scheme in ["https", "http"]:
            try:
                r = httpx.get(
                    f"{scheme}://{host}",
                    timeout=10,
                    follow_redirects=True
                )

                # Analyze Headers
                headers = dict(r.headers)
                result["headers"] = headers

                # Server
                if "server" in headers:
                    result["server"] = headers["server"]
                    print(f"     Server: {headers['server']}")

                # Powered By
                if "x-powered-by" in headers:
                    result["technologies"].append(headers["x-powered-by"])
                    print(f"     Powered By: {headers['x-powered-by']}")

                # Security Headers Check
                security_headers = [
                    "x-frame-options",
                    "x-xss-protection",
                    "content-security-policy",
                    "strict-transport-security",
                    "x-content-type-options"
                ]
                missing = []
                for h in security_headers:
                    if h not in headers:
                        missing.append(h)

                if missing:
                    print(f"     ⚠️  Missing Security Headers: {', '.join(missing)}")
                    result["missing_headers"] = missing

                # Analyze HTML
                soup = BeautifulSoup(r.text, "html.parser")

                # Detect WordPress
                if "wp-content" in r.text or "wp-includes" in r.text:
                    result["cms"] = "WordPress"
                    print(f"     CMS: WordPress detected!")

                # Detect jQuery version
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if "jquery" in src.lower():
                        result["frameworks"].append(f"jQuery ({src})")
                        print(f"     Framework: jQuery found")

                # Detect React
                if "react" in r.text.lower():
                    result["frameworks"].append("React")
                    print(f"     Framework: React detected")

                # Detect Angular
                if "ng-version" in r.text or "angular" in r.text.lower():
                    result["frameworks"].append("Angular")
                    print(f"     Framework: Angular detected")

                # Detect Laravel
                if "laravel" in r.text.lower() or "XSRF-TOKEN" in str(headers):
                    result["technologies"].append("Laravel")
                    print(f"     Tech: Laravel detected")

                # Detect PHP
                if "x-powered-by" in headers and "php" in headers["x-powered-by"].lower():
                    result["technologies"].append("PHP")
                    print(f"     Tech: PHP detected")

                break

            except Exception as e:
                print(f"     Error on {scheme}: {e}")
                continue

        all_results.append(result)
        save_tech(scan_id, result)

    print(f"\n✅ Tech Fingerprinting complete!")
    return all_results

def save_tech(scan_id, result):
    conn = get_connection()
    cursor = conn.cursor()
    tech_summary = ", ".join(result["technologies"] + result["frameworks"])
    if result["cms"]:
        tech_summary = result["cms"] + ", " + tech_summary
    cursor.execute("""
        INSERT INTO vulnerabilities (scan_id, host, vuln_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, (
        scan_id,
        result["host"],
        "Tech Stack",
        "Info",
        f"Server: {result['server']} | Tech: {tech_summary}"
    ))
    if result.get("missing_headers"):
        cursor.execute("""
            INSERT INTO vulnerabilities (scan_id, host, vuln_type, severity, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            result["host"],
            "Missing Security Headers",
            "Medium",
            f"Missing: {', '.join(result['missing_headers'])}"
        ))
    conn.commit()
    conn.close()
