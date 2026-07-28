"""
Audit Reporter Module
Formats audit scan findings into structured JSON, Markdown, or HTML security reports.
"""

import json

class AuditReporter:
    def format_json(self, findings, scan_metadata=None):
        report = {
            "summary": {
                "total_findings": len(findings),
                "severity_counts": self._count_severities(findings),
            },
            "findings": findings
        }
        if scan_metadata:
            report["metadata"] = scan_metadata
        return json.dumps(report, indent=2)

    def format_markdown(self, findings, scan_metadata=None):
        md = []
        md.append("# 🛡️ Cryptographic Security Audit Report\n")
        
        severities = self._count_severities(findings)
        md.append("## Audit Executive Summary")
        md.append(f"- **Total Vulnerabilities Detected**: {len(findings)}")
        md.append(f"- **CRITICAL**: {severities.get('CRITICAL', 0)}")
        md.append(f"- **HIGH**: {severities.get('HIGH', 0)}")
        md.append(f"- **MEDIUM**: {severities.get('MEDIUM', 0)}")
        md.append(f"- **LOW**: {severities.get('LOW', 0)}\n")
        md.append("---\n")

        md.append("## Detailed Audit Findings\n")

        for idx, f in enumerate(findings, 1):
            rule_id = f.get("rule_id", f"CRYPTO-{idx:03d}")
            md.append(f"### `{rule_id}` — {f['rule_name']}")
            md.append(f"**Finding**: {f['description']}")
            md.append(f"**Severity**: `{f['severity']}`")
            md.append(f"**CWE Standard**: {f.get('cwe', 'N/A')}")
            md.append(f"**File Evidence**: `{f['file']}:{f['line']}`")
            md.append("```code")
            md.append(f"{f['evidence']}")
            md.append("```")
            md.append(f"**Contextual Risk (AI Analysis)**:\n{f.get('ai_risk_explanation', f['description'])}\n")
            
            patch = f.get("remediation_patch", {})
            if patch and "after" in patch:
                md.append("**Remediation Fix**:")
                md.append("```diff")
                md.append(f"- {patch.get('before', f['evidence'])}")
                md.append(f"+ {patch.get('after', '')}")
                md.append("```\n")
            else:
                md.append(f"**Recommendation**: {f['remediation']}\n")

            refs = f.get("references", [])
            if refs:
                md.append(f"**References**: {', '.join(refs)}\n")

            md.append("---\n")

        return "\n".join(md)

    def _count_severities(self, findings):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts
