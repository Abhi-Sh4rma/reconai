import sublist3r
import subprocess
from backend.database.db import get_connection

def enumerate_subdomains(domain, scan_id):
    print(f"\n🔍 Starting subdomain enumeration for: {domain}")
    subdomains = set()

    # Method 1: Sublist3r
    try:
        print("  → Running Sublist3r...")
        results = sublist3r.main(
            domain,
            40,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None
        )
        if results:
            subdomains.update(results)
            print(f"  → Sublist3r found: {len(results)} subdomains")
    except Exception as e:
        print(f"  → Sublist3r error: {e}")

    # Method 2: Amass (passive mode)
    try:
        print("  → Running Amass (passive)...")
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-timeout", "2"],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.stdout:
            amass_results = result.stdout.strip().split("\n")
            # Filter only valid subdomains
            clean = [
                r.strip() for r in amass_results
                if domain in r
                and "-->" not in r
                and "Netblock" not in r
                and "ASN" not in r
                and "IPAddress" not in r
                and " " not in r.strip()
            ]
            subdomains.update(clean)
            print(f"  → Amass found: {len(clean)} subdomains")
    except Exception as e:
        print(f"  → Amass error: {e}")

    # Clean results
    subdomains = list(filter(
        lambda x: x and 'No assets' not in x,
        subdomains
    ))

    # Save to database
    save_subdomains(scan_id, subdomains)

    print(f"\n✅ Total unique subdomains found: {len(subdomains)}")
    return subdomains


def save_subdomains(scan_id, subdomains):
    conn = get_connection()
    cursor = conn.cursor()
    for sub in subdomains:
        cursor.execute(
            "INSERT INTO subdomains (scan_id, subdomain) VALUES (?, ?)",
            (scan_id, sub)
        )
    conn.commit()
    conn.close()
