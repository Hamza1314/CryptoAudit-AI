/**
 * Client-Side In-Browser Static Scanner Module
 */

class ClientStaticScanner {
  constructor(rules = CRYPTO_RULES) {
    this.rules = rules;
  }

  scanFile(fileName, content) {
    const findings = [];
    const lines = content.split(/\r?\n/);

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineText = line.trim();

      if (!lineText) return;

      this.rules.forEach(rule => {
        rule.patterns.forEach(pattern => {
          if (pattern.test(line)) {
            findings.push({
              rule_id: rule.id,
              rule_name: rule.name,
              category: rule.category,
              severity: rule.severity,
              cwe: rule.cwe,
              file: fileName,
              line: lineNum,
              evidence: line.trim(),
              description: rule.description,
              remediation: rule.remediation,
              references: rule.references
            });
          }
        });
      });
    });

    return findings;
  }

  scanFileList(fileList) {
    const allFindings = [];
    fileList.forEach(f => {
      const fileFindings = this.scanFile(f.name, f.content);
      allFindings.push(...fileFindings);
    });
    return allFindings;
  }
}
