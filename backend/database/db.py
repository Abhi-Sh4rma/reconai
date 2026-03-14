import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "reconai.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            subdomain TEXT,
            ip TEXT,
            is_alive INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            host TEXT,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            host TEXT,
            vuln_type TEXT,
            severity TEXT,
            description TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        );
    """)

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

if __name__ == "__main__":
    init_db()
