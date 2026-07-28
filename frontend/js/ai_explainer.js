/**
 * Client-Side AI Explanation & Code Patch Module
 */

class ClientAIExplainer {
  enrichFinding(finding) {
    return {
      ...finding,
      ai_risk_explanation: this.generateRiskExplanation(finding),
      remediation_patch: this.generateDiffPatch(finding)
    };
  }

  generateRiskExplanation(finding) {
    const { rule_id, evidence, file, line } = finding;
    
    switch (rule_id) {
      case "CRYPTO-001":
        return `At line ${line} in \`${file}\`, the application uses legacy MD5/SHA-1 hashing (\`${evidence}\`). Collision resistance is broken, allowing attackers to manipulate payload checksums or compromise integrity.`;
      case "CRYPTO-002":
        return `In \`${file}:${line}\`, password hashes are generated using fast general hashing without memory-hard iteration algorithms (\`${evidence}\`). Leaked database hashes can be cracked in seconds via GPU rainbow tables.`;
      case "CRYPTO-003":
        return `Hardcoded credential or key detected at line ${line} in \`${file}\` (\`${evidence}\`). Exposing private keys in client/server source code breaks authentication security.`;
      case "CRYPTO-004":
        return `In \`${file}:${line}\`, non-cryptographic PRNG (\`${evidence}\`) is used. Predictable internal seed states allow adversaries to guess session tokens or secret pins.`;
      case "CRYPTO-005":
        return `AES-ECB cipher mode identified in \`${file}:${line}\` (\`${evidence}\`). ECB encrypts matching block inputs into identical block ciphertexts, exposing structural patterns in data.`;
      case "CRYPTO-009":
        return `TLS/SSL verification is disabled at line ${line} in \`${file}\` (\`${evidence}\`). This exposes all network communication to Man-In-The-Middle (MITM) inspection and interception.`;
      case "CRYPTO-010":
        return `Unverified or 'none' algorithm JWT in \`${file}:${line}\` (\`${evidence}\`). Attackers can forge arbitrary JWT signatures and impersonate high-privilege administrators.`;
      default:
        return `Cryptographic security vulnerability in \`${file}\` at line ${line}. Evidence code \`${evidence}\` fails standard cryptographic guidelines.`;
    }
  }

  generateDiffPatch(finding) {
    const { rule_id, evidence } = finding;

    if (rule_id === "CRYPTO-001") {
      return {
        before: evidence,
        after: evidence.replace(/md5|sha1/gi, "sha256")
      };
    } else if (rule_id === "CRYPTO-002") {
      return {
        before: evidence,
        after: "// Use Argon2id for secure password hashing\nconst argon2 = require('argon2');\nconst hash = await argon2.hash(password);"
      };
    } else if (rule_id === "CRYPTO-003") {
      return {
        before: evidence,
        after: "const SECRET_KEY = process.env.APP_SECRET_KEY; // Read securely from system environment"
      };
    } else if (rule_id === "CRYPTO-004") {
      return {
        before: evidence,
        after: evidence.replace("Math.random()", "crypto.randomBytes(16).toString('hex')").replace("random.randint", "secrets.randbelow")
      };
    } else if (rule_id === "CRYPTO-005") {
      return {
        before: evidence,
        after: evidence.replace("MODE_ECB", "MODE_GCM").replace("aes-128-ecb", "aes-256-gcm")
      };
    } else if (rule_id === "CRYPTO-009") {
      return {
        before: evidence,
        after: evidence.replace("verify=False", "verify=True").replace("rejectUnauthorized: false", "rejectUnauthorized: true")
      };
    }

    return {
      before: evidence,
      after: `// Remediation: ${finding.remediation}`
    };
  }
}
