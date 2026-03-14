import httpx
from backend.database.db import get_connection

def run_vuln_checks(scan_id, hosts):
    print(f"\n⚡ Starting Vulnerability Checks for {len(hosts)} host(s)...")
    all_findings = []

    for host in hosts:
        print(f"\n  → Checking: {host}")

        # Check 1: Open Redirect
        findings = check_open_redirect(host)
        all_findings.extend(findings)

        # Check 2: Sensitive Files
        findings = check_sensitive_files(host)
        all_findings.extend(findings)

        # Check 3: Cookie Security
        findings = check_cookie_security(host)
        all_findings.extend(findings)

        # Check 4: Alternative Ports
        findings = check_alt_ports(host)
        all_findings.extend(findings)

        # Check 5: CORS Misconfiguration
        findings = check_cors(host)
        all_findings.extend(findings)

        # Save all findings
        for finding in all_findings:
            save_finding(scan_id, host, finding)

    print(f"\n✅ Vulnerability Checks complete!")
    print(f"   Total findings: {len(all_findings)}")
    return all_findings


def check_open_redirect(host):
    findings = []
    print(f"     → Checking Open Redirect...")
    payloads = [
        f"https://{host}/?url=https://evil.com",
        f"https://{host}/?redirect=https://evil.com",
        f"https://{host}/?next=https://evil.com",
        f"https://{host}/?return=https://evil.com",
    ]
    try:
        for payload in payloads:
            r = httpx.get(payload, timeout=5, follow_redirects=False)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get("location", "")
                if "evil.com" in location:
                    findings.append({
                        "type": "Open Redirect",
                        "severity": "Medium",
                        "detail": f"Redirects to evil.com via: {payload}"
                    })
                    print(f"     ⚠️  Open Redirect found: {payload}")
    except Exception as e:
        print(f"     Open Redirect check error: {e}")
    if not findings:
        print(f"     ✅ No open redirect found")
    return findings


def check_sensitive_files(host):
    findings = []
    print(f"     → Checking Sensitive Files...")
    paths = [
        "/.git/config",
        "/.env",
        "/robots.txt",
        "/sitemap.xml",
        "/.htaccess",
        "/backup.zip",
        "/admin",
        "/admin/login",
        "/api/v1",
        "/api/v2",
        "/.well-known/security.txt",
        "/phpinfo.php",
        "/config.php",
        "/wp-admin",
        "/console"
    ]
    try:
        for path in paths:
            url = f"https://{host}{path}"
            r = httpx.get(url, timeout=5, follow_redirects=True)
            if r.status_code == 200:
                findings.append({
                    "type": "Sensitive File Exposed",
                    "severity": "High" if path in ["/.git/config", "/.env", "/phpinfo.php"] else "Medium",
                    "detail": f"Accessible: {url} (HTTP {r.status_code})"
                })
                print(f"     ⚠️  Found: {url} → {r.status_code}")
            elif r.status_code == 403:
                print(f"     🔒 Forbidden: {url} → 403")
    except Exception as e:
        pass
    if not findings:
        print(f"     ✅ No sensitive files exposed")
    return findings


def check_cookie_security(host):
    findings = []
    print(f"     → Checking Cookie Security...")
    try:
        r = httpx.get(f"https://{host}", timeout=5, follow_redirects=True)
        cookies = r.headers.get("set-cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                findings.append({
                    "type": "Cookie Missing HttpOnly",
                    "severity": "Medium",
                    "detail": f"Cookie without HttpOnly flag: {cookies[:100]}"
                })
                print(f"     ⚠️  Cookie missing HttpOnly flag")
            if "secure" not in cookies.lower():
                findings.append({
                    "type": "Cookie Missing Secure Flag",
                    "severity": "Medium",
                    "detail": f"Cookie without Secure flag: {cookies[:100]}"
                })
                print(f"     ⚠️  Cookie missing Secure flag")
            if not findings:
                print(f"     ✅ Cookies look secure")
        else:
            print(f"     ✅ No cookies set")
    except Exception as e:
        print(f"     Cookie check error: {e}")
    return findings


def check_alt_ports(host):
    findings = []
    print(f"     → Checking Alt Ports (8080, 8443)...")
    alt_ports = [
        (8080, "http"),
        (8443, "https")
    ]
    try:
        for port, scheme in alt_ports:
            url = f"{scheme}://{host}:{port}"
            r = httpx.get(url, timeout=5, follow_redirects=True)
            if r.status_code < 500:
                findings.append({
                    "type": "Service on Alt Port",
                    "severity": "Medium",
                    "detail": f"Service running on {url} → HTTP {r.status_code}"
                })
                print(f"     ⚠️  Service found on {url} → {r.status_code}")
    except Exception as e:
        print(f"     Alt port check: {e}")
    if not findings:
        print(f"     ✅ No services on alt ports")
    return findings


def check_cors(host):
    findings = []
    print(f"     → Checking CORS Misconfiguration...")
    try:
        headers = {"Origin": "https://evil.com"}
        r = httpx.get(f"https://{host}", headers=headers, timeout=5)
        acao = r.headers.get("access-control-allow-origin", "")
        if acao == "*" or "evil.com" in acao:
            findings.append({
                "type": "CORS Misconfiguration",
                "severity": "High",
                "detail": f"Access-Control-Allow-Origin: {acao}"
            })
            print(f"     ⚠️  CORS Misconfiguration: {acao}")
        else:
            print(f"     ✅ CORS looks fine")
    except Exception as e:
        print(f"     CORS check error: {e}")
    return findings


def save_finding(scan_id, host, finding):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (scan_id, host, vuln_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, (
        scan_id,
        host,
        finding["type"],
        finding["severity"],
        finding["detail"]
    ))
    conn.commit()
    conn.close()
