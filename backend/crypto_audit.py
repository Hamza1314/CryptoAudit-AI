#!/usr/bin/env python3
"""
Cryptographic Security Audit Platform CLI Tool
Usage:
    python backend/crypto_audit.py --path ./test_samples/python_auth_app --format markdown
"""

import argparse
import os
import sys

# Ensure UTF-8 encoding on Windows standard streams
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

from scanner.engine import ScannerEngine
from scanner.ai_enricher import AIEnricher
from scanner.reporter import AuditReporter

def main():
    parser = argparse.ArgumentParser(description="Cryptographic Security Audit Static Scanner")
    parser.add_argument("--path", "-p", required=True, help="Path to codebase directory or single file to audit")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="markdown", help="Output report format")
    parser.add_argument("--output", "-o", help="File path to save report (prints to stdout if omitted)")
    
    args = parser.parse_args()

    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"[!] Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting Cryptographic Security Audit scan on: {target_path} ...", file=sys.stderr)
    
    engine = ScannerEngine()
    raw_findings = engine.scan_directory(target_path)
    print(f"[*] Raw findings detected: {len(raw_findings)}", file=sys.stderr)

    print("[*] Running AI Analysis & Remediation Layer ...", file=sys.stderr)
    enricher = AIEnricher()
    enriched_findings = enricher.enrich_all(raw_findings)

    reporter = AuditReporter()
    if args.format == "json":
        report_output = reporter.format_json(enriched_findings)
    else:
        report_output = reporter.format_markdown(enriched_findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_output)
        print(f"[+] Audit report successfully saved to: {args.output}", file=sys.stderr)
    else:
        print("\n" + report_output)

if __name__ == "__main__":
    main()
