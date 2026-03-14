import dns.resolver
import dns.reversename
import httpx
from backend.database.db import get_connection

CLOUDFLARE_RANGES = [
    "103.21.", "103.22.", "103.31.", "104.16.", "104.17.",
    "108.162.", "131.0.", "141.101.", "162.158.", "172.64.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    "173.245.", "188.114.", "190.93.", "197.234.", "198.41."
]

def resolve_subdomains(scan_id, subdomains):
    print(f"\n🌐 Starting DNS Resolution for {len(subdomains)} subdomains...")
    resolved = []

    for subdomain in subdomains:
        print(f"\n  → Resolving: {subdomain}")
        result = {
            "subdomain": subdomain,
            "ip": None,
            "is_alive": False,
            "behind_cdn": False,
            "cdn_name": None
        }

        # Step 1: Resolve IP
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            ip = str(answers[0])
            result["ip"] = ip
            print(f"     IP: {ip}")

            # Step 2: Check CDN
            cdn = detect_cdn(ip)
            if cdn:
                result["behind_cdn"] = True
                result["cdn_name"] = cdn
                print(f"     CDN: {cdn}")

        except Exception as e:
            print(f"     DNS Error: {e}")

        # Step 3: Check if alive
        try:
            r = httpx.get(f"http://{subdomain}", timeout=5, follow_redirects=True)
            result["is_alive"] = True
            print(f"     Status: ALIVE (HTTP {r.status_code})")
        except:
            try:
                r = httpx.get(f"https://{subdomain}", timeout=5, follow_redirects=True)
                result["is_alive"] = True
                print(f"     Status: ALIVE (HTTPS {r.status_code})")
            except:
                print(f"     Status: DEAD or unreachable")

        resolved.append(result)
        save_dns_result(scan_id, result)

    print(f"\n✅ DNS Resolution complete!")
    alive = [r for r in resolved if r["is_alive"]]
    print(f"   Alive hosts: {len(alive)}/{len(resolved)}")
    return resolved

def detect_cdn(ip):
    for cf in CLOUDFLARE_RANGES:
        if ip.startswith(cf):
            return "Cloudflare"
    return None

def save_dns_result(scan_id, result):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE subdomains
        SET ip = ?, is_alive = ?
        WHERE scan_id = ? AND subdomain = ?
    """, (
        result["ip"],
        1 if result["is_alive"] else 0,
        scan_id,
        result["subdomain"]
    ))
    conn.commit()
    conn.close()
