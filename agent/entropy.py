import math
import os
import re
import time

class EntropySecretScanner:
    EXCLUDED_DIRS = {".git", "node_modules", "proc", "sys", "venv", ".venv", "__pycache__"}
    SECRET_PATTERNS = [
        (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS_ACCESS_KEY"),
        (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), "RSA_PRIVATE_KEY"),
        (re.compile(r'(?i)api[_\-]?key\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'), "API_KEY_TOKEN")
    ]

    @staticmethod
    def calculate_shannon_entropy(data_str: str) -> float:
        if not data_str:
            return 0.0
        entropy = 0.0
        length = len(data_str)
        frequencies = {}
        for char in data_str:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def scan_file(self, file_path: str):
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                
            is_config_file = file_path.endswith((".env", ".yaml", ".yml", ".json", ".conf"))
            
            for line_idx, line in enumerate(lines, 1):
                clean_line = line.strip()
                # 1. Regex pattern check
                for pattern, secret_type in self.SECRET_PATTERNS:
                    if pattern.search(clean_line):
                        findings.append({
                            "type": secret_type,
                            "path": file_path,
                            "line": line_idx,
                            "content": clean_line[:50]
                        })
                        break
                
                # 2. Shannon Entropy check for config/env files
                if is_config_file and len(clean_line) > 12:
                    # extract tokens/quotes
                    tokens = re.findall(r'[A-Za-z0-9+/=_\-]{12,}', clean_line)
                    for token in tokens:
                        H = self.calculate_shannon_entropy(token)
                        if H > 4.5:
                            findings.append({
                                "type": "HIGH_ENTROPY_SECRET",
                                "entropy": round(H, 2),
                                "path": file_path,
                                "line": line_idx,
                                "token": token[:20]
                            })
        except Exception:
            pass
        return findings

    def scan_directory(self, root_dir: str):
        all_findings = []
        file_count = 0
        start_time = time.time()
        
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDED_DIRS]
            for file in files:
                file_path = os.path.join(root, file)
                file_count += 1
                findings = self.scan_file(file_path)
                all_findings.extend(findings)
                
        elapsed = time.time() - start_time
        return all_findings, file_count, elapsed

if __name__ == "__main__":
    scanner = EntropySecretScanner()
    # Test formula
    test_str = "AKIAIOSFODNN7EXAMPLE"
    print(f"Entropy of '{test_str}':", scanner.calculate_shannon_entropy(test_str))
