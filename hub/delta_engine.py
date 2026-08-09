import hashlib
import json
import os

class BaselineDeltaEngine:
    """
    Module 3.3: Baseline Delta Engine (System Anomaly Detection)
    Cryptographic baseline analyzer recording SHA-256 hashes of system binaries,
    active processes, and open ports, flagging structural shifts.
    """
    def __init__(self):
        self.baselines = {}

    @staticmethod
    def calculate_file_sha256(file_path: str) -> str:
        if not os.path.exists(file_path):
            return ""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    def record_baseline(self, node_id: str, binary_paths: list, active_processes: list, open_ports: list):
        hashes = {}
        for path in binary_paths:
            if os.path.exists(path):
                hashes[path] = self.calculate_file_sha256(path)
                
        self.baselines[node_id] = {
            "binary_hashes": hashes,
            "active_processes": set(active_processes),
            "open_ports": set(open_ports)
        }
        return self.baselines[node_id]

    def verify_delta(self, node_id: str, current_binary_paths: list, current_processes: list, current_ports: list):
        anomalies = []
        baseline = self.baselines.get(node_id)
        if not baseline:
            return anomalies

        # 1. Binary checksum mismatch
        for path in current_binary_paths:
            if os.path.exists(path):
                current_hash = self.calculate_file_sha256(path)
                expected_hash = baseline["binary_hashes"].get(path)
                if expected_hash and current_hash != expected_hash:
                    anomalies.append({
                        "type": "UNKNOWN_SYSTEM_ANOMALY",
                        "subtype": "SHA-256 Checksum Mismatch",
                        "path": path,
                        "expected_hash": expected_hash,
                        "current_hash": current_hash,
                        "severity": "Critical"
                    })

        # 2. Rogue process / port detection
        new_ports = set(current_ports) - baseline["open_ports"]
        if new_ports:
            anomalies.append({
                "type": "UNKNOWN_SYSTEM_ANOMALY",
                "subtype": "Unmapped Rogue Port/Process Listener",
                "new_ports": list(new_ports),
                "current_processes": current_processes,
                "severity": "High"
            })

        return anomalies

if __name__ == "__main__":
    engine = BaselineDeltaEngine()
    # Test file
    test_bin = "test_binary.bin"
    with open(test_bin, "wb") as f:
        f.write(b"ORIGINAL_BINARY_CONTENT_0000")
        
    engine.record_baseline("node-01", [test_bin], ["systemd"], [80, 443])
    
    # Modify 1 byte in binary
    with open(test_bin, "wb") as f:
        f.write(b"ORIGINAL_BINARY_CONTENT_0001")
        
    anomalies = engine.verify_delta("node-01", [test_bin], ["systemd", "nc"], [80, 443, 9999])
    print("Baseline Anomaly Alerts:", anomalies)
    if os.path.exists(test_bin):
        os.remove(test_bin)
