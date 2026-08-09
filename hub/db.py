import sqlite3
import time
import json
import os
import queue

class DatabaseStack:
    def __init__(self, db_path="vulnera_enterprise.db"):
        self.db_path = db_path
        self.init_db()
        self.scan_queue = queue.Queue()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL,
                last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                os_patch_level TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                cve_id TEXT,
                rule_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                path TEXT NOT NULL,
                host_count INTEGER DEFAULT 1,
                affected_hosts TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_mirror (
                cve_id TEXT PRIMARY KEY,
                package_name TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                affected_version TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cve_lookup 
            ON cve_mirror (package_name, ecosystem, affected_version)
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS delta_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                binary_hash TEXT NOT NULL,
                active_processes TEXT NOT NULL,
                open_ports TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def benchmark_queue_latency(self, iterations=10000):
        start_time = time.time()
        for i in range(iterations):
            self.scan_queue.put({"job_id": i, "payload": "scan_request"})
            _ = self.scan_queue.get()
        elapsed = time.time() - start_time
        return (elapsed / iterations) * 1000

if __name__ == "__main__":
    db = DatabaseStack()
    print("Database initialized with WAL mode & 30s busy timeout.")
