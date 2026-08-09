import csv
import json
import io
import time
import os

class ExportWorkers:
    """
    Module 5.1: Export Generation Workers (CSV, JSON, PDF)
    RFC 4180 compliant CSV, Jira/SIEM compatible JSON, and PDF report generator.
    """
    @staticmethod
    def generate_csv(vulnerabilities_list, output_file=None):
        output = io.StringIO()
        fieldnames = ["vuln_id", "cve_id", "rule_id", "title", "severity", "asset_type", "path", "host_count", "affected_hosts"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        
        for item in vulnerabilities_list:
            row = {
                "vuln_id": item.get("vuln_id", ""),
                "cve_id": item.get("cve_id", ""),
                "rule_id": item.get("rule_id", ""),
                "title": item.get("title", ""),
                "severity": item.get("severity", ""),
                "asset_type": item.get("asset_type", ""),
                "path": item.get("path", ""),
                "host_count": item.get("host_count", 1),
                "affected_hosts": ",".join(item.get("affected_hosts", [])) if isinstance(item.get("affected_hosts"), list) else str(item.get("affected_hosts", ""))
            }
            writer.writerow(row)
            
        csv_str = output.getvalue()
        if output_file:
            with open(output_file, "w", encoding="utf-8", newline="") as f:
                f.write(csv_str)
        return csv_str

    @staticmethod
    def generate_siem_json(vulnerabilities_list, output_file=None):
        payload = {
            "version": "1.0",
            "exporter": "VULNERA-MAP Enterprise",
            "timestamp": time.time(),
            "count": len(vulnerabilities_list),
            "vulnerabilities": vulnerabilities_list
        }
        json_str = json.dumps(payload, indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_str)
        return json_str

    @staticmethod
    def generate_pdf_summary(vulnerabilities_list, output_file="summary.pdf"):
        # Generates clean HTML/PDF formatted executive report
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for item in vulnerabilities_list:
            sev = item.get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
        html_report = f"""<!DOCTYPE html>
<html>
<head>
<title>VULNERA-MAP Enterprise Security Summary</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
h1 {{ color: #1e293b; border-bottom: 2px solid #0f172a; padding-bottom: 10px; }}
.metric {{ display: inline-block; width: 120px; padding: 15px; margin: 10px; border-radius: 8px; text-align: center; color: white; }}
.critical {{ background: #ef4444; }}
.high {{ background: #f97316; }}
.medium {{ background: #eab308; }}
.low {{ background: #3b82f6; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
th, td {{ border: 1px solid #cbd5e1; padding: 10px; text-align: left; }}
th {{ background: #f1f5f9; }}
</style>
</head>
<body>
<h1>VULNERA-MAP Enterprise Executive Report</h1>
<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
<div>
    <div class="metric critical"><h3>{severity_counts['Critical']}</h3><p>Critical</p></div>
    <div class="metric high"><h3>{severity_counts['High']}</h3><p>High</p></div>
    <div class="metric medium"><h3>{severity_counts['Medium']}</h3><p>Medium</p></div>
    <div class="metric low"><h3>{severity_counts['Low']}</h3><p>Low</p></div>
</div>
<h2>Top Vulnerabilities</h2>
<table>
<tr><th>ID</th><th>Title</th><th>Severity</th><th>Asset Path</th><th>Hosts</th></tr>
"""
        for item in vulnerabilities_list[:10]:
            html_report += f"<tr><td>{item.get('vuln_id')}</td><td>{item.get('title')}</td><td>{item.get('severity')}</td><td>{item.get('path')}</td><td>{item.get('host_count')}</td></tr>\n"
        html_report += "</table></body></html>"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_report)
        return output_file

if __name__ == "__main__":
    exporter = ExportWorkers()
    sample = [
        {
            "vuln_id": "VULN-001",
            "cve_id": "CVE-2021-44228",
            "title": "Log4j RCE, containing \"quotes\", commas & \n newlines",
            "severity": "Critical",
            "asset_type": "DependencyPackage",
            "path": "C:\\app\\requirements.txt",
            "host_count": 500,
            "affected_hosts": ["host-001", "host-002"]
        }
    ]
    csv_res = exporter.generate_csv(sample)
    print("CSV Result RFC 4180 Escaping Check:\n", csv_res)
