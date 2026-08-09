import os
import re
import json
import xml.etree.ElementTree as ET

class DependencyManifestExtractor:
    """
    Module 2.3: Dependency Manifest Extractor
    Parses requirements.txt, package.json, go.mod, pom.xml, Cargo.toml.
    Extracts (package_name, ecosystem, version) tuples with edge-case/error handling.
    """
    @staticmethod
    def parse_manifest(file_path: str):
        dependencies = []
        filename = os.path.basename(file_path)
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if filename == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Match pkg==ver or pkg>=ver or pkg~=ver
                    match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=<>]+\s*[a-zA-Z0-9_\-\.]+)?', line)
                    if match:
                        pkg = match.group(1)
                        ver = match.group(2).replace("=", "").strip() if match.group(2) else "latest"
                        dependencies.append({"package": pkg, "ecosystem": "PyPI", "version": ver})

            elif filename == "package.json":
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                for pkg, ver in deps.items():
                    clean_ver = re.sub(r'[\^~>=<]', '', str(ver)).strip()
                    dependencies.append({"package": pkg, "ecosystem": "npm", "version": clean_ver})

            elif filename == "go.mod":
                in_require = False
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and line == ")":
                        in_require = False
                        continue
                    if line.startswith("require ") or in_require:
                        parts = line.replace("require ", "").split()
                        if len(parts) >= 2:
                            dependencies.append({"package": parts[0], "ecosystem": "Go", "version": parts[1]})

            elif filename == "pom.xml":
                root = ET.fromstring(content)
                # Handle namespaces
                ns = {'mvn': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
                deps = root.findall('.//mvn:dependency', ns) if ns else root.findall('.//dependency')
                for dep in deps:
                    group = dep.find('mvn:groupId', ns).text if ns and dep.find('mvn:groupId', ns) is not None else (dep.find('groupId').text if dep.find('groupId') is not None else "")
                    artifact = dep.find('mvn:artifactId', ns).text if ns and dep.find('mvn:artifactId', ns) is not None else (dep.find('artifactId').text if dep.find('artifactId') is not None else "")
                    ver_node = dep.find('mvn:version', ns) if ns else dep.find('version')
                    ver = ver_node.text if ver_node is not None else "unknown"
                    pkg_name = f"{group}:{artifact}" if group else artifact
                    if pkg_name:
                        dependencies.append({"package": pkg_name, "ecosystem": "Maven", "version": ver})

            elif filename == "Cargo.toml":
                in_deps = False
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("[dependencies]"):
                        in_deps = True
                        continue
                    elif line.startswith("[") and in_deps:
                        in_deps = False
                        continue
                    if in_deps and "=" in line:
                        parts = line.split("=")
                        pkg = parts[0].strip()
                        ver = parts[1].strip().strip('"').strip("'")
                        dependencies.append({"package": pkg, "ecosystem": "Cargo", "version": ver})

        except Exception as e:
            # Gracefully handle corrupted manifest files without crashing daemon
            pass

        return dependencies

if __name__ == "__main__":
    extractor = DependencyManifestExtractor()
    sample_reqs = "log4j-core==2.14.1\n# Comment line\nrequests>=2.28.0\n"
    tmp = "requirements.txt"
    with open(tmp, "w") as f:
        f.write(sample_reqs)
    parsed = extractor.parse_manifest(tmp)
    print("Parsed requirements.txt:", parsed)
    if os.path.exists(tmp):
        os.remove(tmp)
