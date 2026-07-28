/**
 * Client-Side Report Export & Rendering Module
 */

class ClientReportBuilder {
  exportJSON(findings, repoName = "Audit Target") {
    const report = {
      target: repoName,
      scan_date: new Date().toISOString(),
      summary: {
        total_findings: findings.length,
        severities: this.countSeverities(findings)
      },
      findings: findings
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    this.downloadFile(dataStr, `crypto_audit_report_${Date.now()}.json`);
  }

  exportMarkdown(findings, repoName = "Audit Target") {
    const lines = [];
    lines.push(`# 🛡️ Cryptographic Security Audit Report: ${repoName}`);
    lines.push(`*Generated on: ${new Date().toLocaleString()}*\n`);
    
    const counts = this.countSeverities(findings);
    lines.push(`## Audit Overview`);
    lines.push(`- **Total Vulnerabilities**: ${findings.length}`);
    lines.push(`- **CRITICAL**: ${counts.CRITICAL}`);
    lines.push(`- **HIGH**: ${counts.HIGH}`);
    lines.push(`- **MEDIUM**: ${counts.MEDIUM}`);
    lines.push(`- **LOW**: ${counts.LOW}\n`);

    lines.push(`## Findings & AI Remediations\n`);

    findings.forEach((f, i) => {
      lines.push(`### ${i + 1}. [${f.severity}] ${f.rule_id}: ${f.rule_name}`);
      lines.push(`- **File Evidence**: \`${f.file}:${f.line}\``);
      lines.push(`- **Code Snippet**: \`${f.evidence}\``);
      lines.push(`- **CWE**: ${f.cwe || 'N/A'}`);
      lines.push(`- **AI Risk Context**:\n  ${f.ai_risk_explanation || f.description}`);
      if (f.remediation_patch) {
        lines.push(`- **Suggested Code Fix**:\n\`\`\`diff\n- ${f.remediation_patch.before}\n+ ${f.remediation_patch.after}\n\`\`\``);
      }
      lines.push(`\n---\n`);
    });

    const dataStr = "data:text/markdown;charset=utf-8," + encodeURIComponent(lines.join("\n"));
    this.downloadFile(dataStr, `crypto_audit_report_${Date.now()}.md`);
  }

  countSeverities(findings) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => {
      const sev = (f.severity || "MEDIUM").toUpperCase();
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return counts;
  }

  downloadFile(dataUri, fileName) {
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataUri);
    downloadAnchor.setAttribute("download", fileName);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }
}
