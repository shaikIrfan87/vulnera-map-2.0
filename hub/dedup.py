import hashlib
import time
import os

class EventTracerAndDeduplicationPipeline:
    """
    Module 4.1: Kernel Event Tracer (< 500ms anomaly alert latency)
    Module 4.2: Vulnerability Aggregation & Deduplication Pipeline
    Fingerprint: SHA256(Asset_Type + Path + CVE_ID_or_Rule_ID)
    """
    def __init__(self):
        self.master_tickets = {}

    @staticmethod
    def generate_fingerprint(asset_type: str, path: str, cve_or_rule_id: str) -> str:
        key = f"{asset_type.strip().lower()}:{path.strip().lower()}:{cve_or_rule_id.strip().lower()}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def process_incoming_vulnerability(self, node_id: str, vuln_data: dict):
        asset_type = vuln_data.get("asset_type", "host")
        path = vuln_data.get("path", "system")
        rule_id = vuln_data.get("cve_id") or vuln_data.get("rule_id") or "UNKNOWN_RULE"
        
        fingerprint = self.generate_fingerprint(asset_type, path, rule_id)
        
        if fingerprint in self.master_tickets:
            ticket = self.master_tickets[fingerprint]
            if node_id not in ticket["affected_hosts"]:
                ticket["affected_hosts"].append(node_id)
                ticket["host_count"] = len(ticket["affected_hosts"])
        else:
            self.master_tickets[fingerprint] = {
                "vuln_id": f"VULN-{fingerprint[:8]}",
                "fingerprint": fingerprint,
                "cve_id": vuln_data.get("cve_id"),
                "rule_id": vuln_data.get("rule_id"),
                "title": vuln_data.get("title", "Vulnerability Finding"),
                "severity": vuln_data.get("severity", "Medium"),
                "asset_type": asset_type,
                "path": path,
                "host_count": 1,
                "affected_hosts": [node_id],
                "created_at": time.time()
            }
        return fingerprint

    def simulate_realtime_event_tracer(self, command_line: str):
        start_time = time.time()
        is_reverse_shell = "nc -e" in command_line or "/bin/sh" in command_line or "socket" in command_line
        latency_ms = (time.time() - start_time) * 1000
        
        event = None
        if is_reverse_shell:
            event = {
                "type": "REALTIME_KERNEL_EVENT",
                "syscall": "sys_enter_execve / sys_enter_connect",
                "command": command_line,
                "severity": "Critical",
                "latency_ms": round(latency_ms, 2)
            }
        return event

if __name__ == "__main__":
    pipeline = EventTracerAndDeduplicationPipeline()
    # Stress test 500 agents reporting same issue
    start = time.time()
    for i in range(500):
        pipeline.process_incoming_vulnerability(
            node_id=f"host-{i:03d}",
            vuln_data={
                "asset_type": "DependencyPackage",
                "path": "requirements.txt",
                "cve_id": "CVE-2021-44228",
                "title": "Log4j Remote Code Execution",
                "severity": "Critical"
            }
        )
    elapsed = time.time() - start
    print(f"Deduplicated 500 reports in {elapsed:.4f}s. Master tickets count:", len(pipeline.master_tickets))
    master_ticket = list(pipeline.master_tickets.values())[0]
    print(f"Master ticket host count: {master_ticket['host_count']} (expected 500)")
