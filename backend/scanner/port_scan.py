import nmap
from backend.database.db import get_connection

COMMON_PORTS = "21,22,23,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017"

def scan_ports(scan_id, hosts):
    print(f"\n🔌 Starting Port Scan for {len(hosts)} host(s)...")
    all_results = []

    nm = nmap.PortScanner()

    for host in hosts:
        print(f"\n  → Scanning: {host}")
        try:
            nm.scan(
                hosts=host,
                ports=COMMON_PORTS,
                arguments="-sV -T4 --open"
            )

            for scanned_host in nm.all_hosts():
                print(f"     Host: {scanned_host} ({nm[scanned_host].state()})")

                for proto in nm[scanned_host].all_protocols():
                    ports = nm[scanned_host][proto].keys()

                    for port in ports:
                        state = nm[scanned_host][proto][port]["state"]
                        service = nm[scanned_host][proto][port]["name"]
                        version = nm[scanned_host][proto][port]["version"]

                        port_info = {
                            "host": host,
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "version": version
                        }

                        print(f"     Port {port}/{proto} → {state} | {service} {version}")
                        all_results.append(port_info)
                        save_port(scan_id, port_info)

        except Exception as e:
            print(f"     Scan error: {e}")

    print(f"\n✅ Port scan complete!")
    print(f"   Open ports found: {len(all_results)}")
    return all_results

def save_port(scan_id, port_info):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ports (scan_id, host, port, protocol, state, service)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        port_info["host"],
        port_info["port"],
        port_info["protocol"],
        port_info["state"],
        f"{port_info['service']} {port_info['version']}".strip()
    ))
    conn.commit()
    conn.close()
