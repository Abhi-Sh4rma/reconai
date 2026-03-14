import requests
from backend.database.db import get_connection

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TECH_KEYWORDS = {
    "Next.js": "nextjs",
    "React": "react",
    "WordPress": "wordpress",
    "Laravel": "laravel",
    "PHP": "php",
    "Apache": "apache",
    "Nginx": "nginx",
    "jQuery": "jquery",
    "Angular": "angular",
    "cloudflare": "cloudflare"
}

def match_cves(scan_id, tech_results):
    print(f"\n🔍 Starting CVE Matching...")
    all_cves = []

    techs_found = []

    for result in tech_results:
        if result.get("server"):
            techs_found.append(result["server"])
        if result.get("cms"):
            techs_found.append(result["cms"])
        techs_found.extend(result.get("technologies", []))
        techs_found.extend(result.get("frameworks", []))

    # Deduplicate
    techs_found = list(set(techs_found))
    print(f"  → Technologies to check: {techs_found}")

    for tech in techs_found:
        keyword = None
        for key, val in TECH_KEYWORDS.items():
            if key.lower() in tech.lower():
                keyword = val
                break

        if not keyword:
            keyword = tech.split()[0].lower()

        print(f"\n  → Searching CVEs for: {tech} (keyword: {keyword})")

        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 5,
                "startIndex": 0
            }

            r = requests.get(NVD_API, params=params, timeout=15)
            data = r.json()

            cves = data.get("vulnerabilities", [])
            print(f"     Found {len(cves)} CVEs")

            for cve in cves:
                cve_data = cve.get("cve", {})
                cve_id = cve_data.get("id", "Unknown")

                # Get description
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description"
                )

                # Get severity
                severity = "Unknown"
                metrics = cve_data.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                elif "cvssMetricV2" in metrics:
                    severity = metrics["cvssMetricV2"][0]["baseSeverity"]

                cve_info = {
                    "tech": tech,
                    "cve_id": cve_id,
                    "severity": severity,
                    "description": description[:300]
                }

                print(f"     {cve_id} → {severity}")
                all_cves.append(cve_info)
                save_cve(scan_id, tech_results[0]["host"], cve_info)

        except Exception as e:
            print(f"     Error fetching CVEs: {e}")

    print(f"\n✅ CVE Matching complete!")
    print(f"   Total CVEs found: {len(all_cves)}")
    return all_cves

def save_cve(scan_id, host, cve_info):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (scan_id, host, vuln_type, severity, description)
        VALUES (?, ?, ?, ?, ?)
    """, (
        scan_id,
        host,
        f"CVE - {cve_info['tech']}",
        cve_info["severity"],
        f"{cve_info['cve_id']}: {cve_info['description']}"
    ))
    conn.commit()
    conn.close()
