"""
Static Scanner Engine
Traverses files, evaluates crypto rules, and collects findings with evidence.
"""

import os

from .rules import compile_rules

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".cpp", ".c", ".h",
    ".hpp", ".php", ".cs", ".rb", ".json", ".yaml", ".yml", ".env"
}

IGNORE_DIRS = {
    ".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv", ".idea", ".vscode"
}

class ScannerEngine:
    def __init__(self):
        self.rules = compile_rules()

    def scan_directory(self, target_path):
        """Recursively scans a target directory or single file."""
        findings = []
        target_path = os.path.abspath(target_path)

        if os.path.isfile(target_path):
            findings.extend(self.scan_file(target_path))
            return findings

        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path, target_path))

        return findings

    def scan_file(self, file_path, base_path=None):
        findings = []
        rel_path = os.path.relpath(file_path, base_path) if base_path else file_path

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            return findings

        for line_num, line in enumerate(lines, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith(("#", "//", "/*", "*", "<!--")):
                # Basic comment check - still evaluate if suspicious pattern exists
                pass

            for rule in self.rules:
                for pattern in rule["compiled_patterns"]:
                    match = pattern.search(line)
                    if match:
                        finding = {
                            "rule_id": rule["id"],
                            "rule_name": rule["name"],
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "cwe": rule["cwe"],
                            "file": rel_path.replace("\\", "/"),
                            "line": line_num,
                            "evidence": line.strip(),
                            "description": rule["description"],
                            "remediation": rule["remediation"],
                            "references": rule["references"],
                            "matched_text": match.group(0)
                        }
                        findings.append(finding)
                        break  # Prevent duplicate hits for the same rule on the same line

        return findings
