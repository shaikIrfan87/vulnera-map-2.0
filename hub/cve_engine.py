import sqlite3
import os
from hub.db import DatabaseStack

class KnownVulnerabilityEngine:
    """
    Module 3.1: Known Vulnerability Engine (NVD / OSV Offline Matcher)
    Cross-references incoming dependency tuples against indexed local CVE records.
    """
    def __init__(self, db_stack: DatabaseStack = None):
        self.db_stack = db_stack or DatabaseStack()
        self.seed_offline_cve_mirror()

    def seed_offline_cve_mirror(self):
        conn = self.db_stack.get_connection()
        cursor = conn.cursor()
        
        # Seed test CVE records including Log4j
        cves = [
            ("CVE-2021-44228", "log4j-core", "Maven", "2.14.1", "Critical", "Apache Log4j2 Remote Code Execution"),
            ("CVE-2021-44228", "log4j-core", "PyPI", "2.14.1", "Critical", "Apache Log4j2 Remote Code Execution"),
            ("CVE-2023-30861", "flask", "PyPI", "2.2.0", "High", "Flask session cookie disclosure"),
            ("CVE-2023-26136", "tough-cookie", "npm", "2.5.0", "High", "Prototype Pollution in tough-cookie")
        ]
        
        for cve in cves:
            cursor.execute("""
                INSERT OR REPLACE INTO cve_mirror 
                (cve_id, package_name, ecosystem, affected_version, severity, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, cve)
            
        conn.commit()
        conn.close()

    def match_dependencies(self, dep_tuples):
        matches = []
        conn = self.db_stack.get_connection()
        cursor = conn.cursor()
        
        for dep in dep_tuples:
            pkg = dep.get("package")
            eco = dep.get("ecosystem")
            ver = dep.get("version")
            
            cursor.execute("""
                SELECT cve_id, severity, description FROM cve_mirror
                WHERE package_name = ? AND affected_version = ?
            """, (pkg, ver))
            
            rows = cursor.fetchall()
            for row in rows:
                matches.append({
                    "cve_id": row["cve_id"],
                    "package": pkg,
                    "ecosystem": eco,
                    "version": ver,
                    "severity": row["severity"],
                    "description": row["description"]
                })
                
        conn.close()
        return matches

if __name__ == "__main__":
    engine = KnownVulnerabilityEngine()
    test_deps = [{"package": "log4j-core", "ecosystem": "Maven", "version": "2.14.1"}]
    found = engine.match_dependencies(test_deps)
    print("Offline CVE Match Results:", found)
