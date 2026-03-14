import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from backend.database.db import init_db, get_connection
from backend.scanner.subdomain import enumerate_subdomains
from backend.scanner.dns_resolve import resolve_subdomains
from backend.scanner.port_scan import scan_ports
from backend.scanner.tech_detect import detect_technologies
from backend.scanner.cve_match import match_cves
from backend.scanner.vuln_check import run_vuln_checks
from backend.ai.report_gen import generate_report
from backend.pdf.export import generate_pdf

def print_banner():
    print("""
╔═══════════════════════════════════════════╗
║           ReconAI Security Scanner        ║
║      Automated Recon & Vuln Detection     ║
║          Built by: Abhishek Sharma        ║
╚═══════════════════════════════════════════╝
    """)

def create_scan(domain):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (domain, status) VALUES (?, ?)",
        (domain, "running")
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id

def update_scan_status(scan_id, status):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scans SET status = ? WHERE id = ?",
        (status, scan_id)
    )
    conn.commit()
    conn.close()

def print_summary(findings):
    print("\n" + "="*50)
    print("📊 SCAN SUMMARY")
    print("="*50)

    subdomains = findings["subdomains"]
    ports = findings["ports"]
    vulns = findings["vulnerabilities"]

    print(f"\n🌐 Subdomains Found: {len(subdomains)}")
    for s in subdomains:
        status = "✅ Alive" if s["is_alive"] else "❌ Dead"
        print(f"   → {s['subdomain']} | {s['ip'] or 'No IP'} | {status}")

    print(f"\n🔌 Open Ports: {len(ports)}")
    for p in ports:
        print(f"   → Port {p['port']}/{p['protocol']} | {p['service']}")

    print(f"\n⚠️  Vulnerabilities: {len(vulns)}")
    critical = [v for v in vulns if v["severity"] == "CRITICAL"]
    high = [v for v in vulns if v["severity"] == "HIGH"]
    medium = [v for v in vulns if v["severity"] == "Medium"]
    info = [v for v in vulns if v["severity"] in ["Info", "Unknown"]]

    print(f"   🔴 Critical : {len(critical)}")
    print(f"   🟠 High     : {len(high)}")
    print(f"   🟡 Medium   : {len(medium)}")
    print(f"   🔵 Info     : {len(info)}")
    print("="*50)

def fetch_all_findings(scan_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM subdomains WHERE scan_id = ?", (scan_id,))
    subdomains = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM ports WHERE scan_id = ?", (scan_id,))
    ports = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
    vulns = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return {
        "subdomains": subdomains,
        "ports": ports,
        "vulnerabilities": vulns
    }

def run_scan(domain):
    print_banner()
    print(f"🎯 Target: {domain}")
    print(f"🚀 Starting full recon pipeline...\n")

    # Initialize DB
    init_db()

    # Create scan record
    scan_id = create_scan(domain)
    print(f"📁 Scan ID: {scan_id}")

    try:
        # Stage 1: Subdomain Enumeration
        print("\n[1/6] 🔍 Subdomain Enumeration")
        subdomains = enumerate_subdomains(domain, scan_id)

        # Add main domain if no subdomains found
        all_hosts = [domain]
        if subdomains:
            all_hosts.extend(subdomains)
        all_hosts = list(set(all_hosts))

        # Stage 2: DNS Resolution
        print("\n[2/6] 🌐 DNS Resolution")
        dns_results = resolve_subdomains(scan_id, all_hosts)

        # Only scan alive hosts
        alive_hosts = [r["subdomain"] for r in dns_results if r["is_alive"]]
        if not alive_hosts:
            alive_hosts = [domain]

        # Stage 3: Port Scanning
        print("\n[3/6] 🔌 Port Scanning")
        port_results = scan_ports(scan_id, alive_hosts)

        # Stage 4: Tech Fingerprinting
        print("\n[4/6] 🔎 Tech Fingerprinting")
        tech_results = detect_technologies(scan_id, alive_hosts)

        # Stage 5: CVE Matching
        print("\n[5/6] 🛡️  CVE Matching")
        cve_results = match_cves(scan_id, tech_results)

        # Stage 6: Vulnerability Checks
        print("\n[6/6] ⚡ Vulnerability Checks")
        vuln_results = run_vuln_checks(scan_id, alive_hosts)

        # Update scan status
        update_scan_status(scan_id, "completed")

        # Print Summary
        findings = fetch_all_findings(scan_id)
        print_summary(findings)

        # Ask user to generate PDF
        print("\n" + "="*50)
        choice = input("📄 Generate PDF Report? (yes/no): ").strip().lower()

        if choice in ["yes", "y"]:
            print("\n🤖 Generating AI Report...")
            groq_key = os.getenv("GROQ_API_KEY")
            report_text = generate_report(scan_id, groq_key)

            if report_text:
                print("\n📄 Generating PDF...")
                pdf_path = generate_pdf(domain, report_text, findings)
                print(f"\n✅ PDF saved to: {pdf_path}")
            else:
                print("❌ AI Report generation failed")
        else:
            print("\n✅ Scan complete! PDF skipped.")

    except Exception as e:
        print(f"\n❌ Scan error: {e}")
        update_scan_status(scan_id, "failed")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m backend.main <domain>")
        print("Example: python3 -m backend.main staging.bwishernepal.com")
        sys.exit(1)

    domain = sys.argv[1]
    run_scan(domain)
