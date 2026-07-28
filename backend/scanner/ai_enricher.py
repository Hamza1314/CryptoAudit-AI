"""
AI Analysis & Remediation Layer
Enriches findings with contextual risk explanations, vulnerability impact, code diff remediation patches, and security standards references.
"""

class AIEnricher:
    def enrich_finding(self, finding):
        """Synthesizes AI risk explanation and concrete code fix diff."""
        file_name = finding["file"]
        line_num = finding["line"]
        evidence = finding["evidence"]
        rule_id = finding["rule_id"]

        ai_risk_explanation = self._generate_risk_explanation(finding)
        remediation_patch = self._generate_code_patch(finding)

        enriched = dict(finding)
        enriched["ai_risk_explanation"] = ai_risk_explanation
        enriched["remediation_patch"] = remediation_patch
        return enriched

    def enrich_all(self, findings):
        return [self.enrich_finding(f) for f in findings]

    def _generate_risk_explanation(self, finding):
        rule_id = finding["rule_id"]
        evidence = finding["evidence"]
        file = finding["file"]

        explanations = {
            "CRYPTO-001": f"In `{file}`, the application computes a hash using legacy MD5/SHA-1 (`{evidence}`). Modern hardware can compute billions of MD5/SHA-1 hashes per second. Attackers can forge hash collisions or construct pre-image payloads, breaching integrity verification.",
            "CRYPTO-002": f"The pattern in `{file}` (`{evidence}`) indicates credentials or authentication hashes are stored with fast general-purpose algorithms or weak iterations. An attacker with database access can reverse these credentials instantly via pre-computed rainbow tables.",
            "CRYPTO-003": f"Hardcoded credential or key detected in `{file}` (`{evidence}`). Hardcoded keys in source control are exposed to anyone with code access and cannot be rotated without re-deploying code binaries.",
            "CRYPTO-004": f"The use of standard PRNG in `{file}` (`{evidence}`) generates predictable numbers based on system clock or initial seed. Attackers can forecast future outputs, hijacking tokens, session keys, or password reset codes.",
            "CRYPTO-005": f"AES-ECB mode in `{file}` (`{evidence}`) encrypts identical 16-byte plaintext blocks into identical ciphertext blocks. Attackers can analyze ciphertext patterns to infer underlying plaintext without knowing the key (e.g. Tux ECB penguin effect).",
            "CRYPTO-006": f"Weak key size or cipher in `{file}` (`{evidence}`). Keys under 2048-bit RSA or legacy ciphers like DES/3DES/RC4 can be cracked with accessible computational resources or exploited via known attacks (e.g. Sweet32).",
            "CRYPTO-007": f"Deprecated cryptographic function in `{file}` (`{evidence}`). Deprecated APIs lack security maintenance, may contain memory leaks, and fail modern compliance checks.",
            "CRYPTO-008": f"Static key or fixed IV in `{file}` (`{evidence}`). Reusing IVs in stream or block ciphers exposes plaintext XOR combinations, completely breaking ciphertext confidentiality.",
            "CRYPTO-009": f"Disabled TLS certificate verification in `{file}` (`{evidence}`). Disabling SSL check allows any adversary on the same local network, Wi-Fi, or router to intercept, modify, or inject traffic unnoticed.",
            "CRYPTO-010": f"Unsafe JWT configuration in `{file}` (`{evidence}`). Allowing `alg: 'none'` or skipping signature validation permits unauthenticated attackers to forge arbitrary user claims and elevate privileges."
        }

        return explanations.get(
            rule_id,
            f"Vulnerability identified in `{file}` at line {finding['line']}. Code segment `{evidence}` violates cryptographic best practice `{finding['rule_name']}`."
        )

    def _generate_code_patch(self, finding):
        evidence = finding["evidence"]
        rule_id = finding["rule_id"]

        if rule_id == "CRYPTO-001":
            return {
                "before": evidence,
                "after": evidence.replace("md5", "sha256").replace("sha1", "sha256").replace("MD5", "SHA-256").replace("SHA1", "SHA-256")
            }
        elif rule_id == "CRYPTO-002":
            return {
                "before": evidence,
                "after": "# Recommended: Use Argon2id or bcrypt\nimport argon2\nph = argon2.PasswordHasher()\nhash = ph.hash(password)"
            }
        elif rule_id == "CRYPTO-003":
            return {
                "before": evidence,
                "after": "import os\nSECRET_KEY = os.environ.get('APP_SECRET_KEY')  # Loaded from secure environment"
            }
        elif rule_id == "CRYPTO-004":
            return {
                "before": evidence,
                "after": evidence.replace("random.randint", "secrets.randbelow").replace("random.random()", "secrets.token_hex(16)").replace("Math.random()", "crypto.randomBytes(16).toString('hex')")
            }
        elif rule_id == "CRYPTO-005":
            return {
                "before": evidence,
                "after": evidence.replace("AES.MODE_ECB", "AES.MODE_GCM").replace("AES/ECB/", "AES/GCM/")
            }
        elif rule_id == "CRYPTO-009":
            return {
                "before": evidence,
                "after": evidence.replace("verify=False", "verify=True").replace("rejectUnauthorized: false", "rejectUnauthorized: true")
            }
        elif rule_id == "CRYPTO-010":
            return {
                "before": evidence,
                "after": "jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Enforce strong algorithm and signature verification"
            }

        return {
            "before": evidence,
            "after": f"# Replace with secure primitive: {finding['remediation']}"
        }
