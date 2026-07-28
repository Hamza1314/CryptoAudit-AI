"""
Cryptographic Audit Rules Engine
Defines detection patterns, severity levels, CWE mappings, and vulnerability metadata.
"""

import re

RULES = [
    {
        "id": "CRYPTO-001",
        "name": "Weak Hashing Algorithm (MD5 / SHA-1)",
        "category": "Weak Hashing Algorithms",
        "severity": "HIGH",
        "cwe": "CWE-328",
        "patterns": [
            r"hashlib\.(md5|sha1)\s*\(",
            r"Crypto\.Hash\.(MD5|SHA1)",
            r"crypto\.createHash\(\s*['\"](md5|sha1)['\"]\s*\)",
            r"MessageDigest\.getInstance\(\s*['\"](MD5|SHA-1|SHA1)['\"]\s*\)",
            r"crypto/md5|crypto/sha1",
            r"EVP_(md5|sha1)\s*\(\)",
        ],
        "description": "Usage of MD5 or SHA-1 detected. These algorithms are cryptographically broken for collision resistance.",
        "remediation": "Replace with SHA-256, SHA-384, or SHA-3 for general hashing. Use Argon2id, bcrypt, or scrypt for password hashing.",
        "references": ["https://cwe.mitre.org/data/definitions/328.html", "NIST SP 800-131A Rev 2"]
    },
    {
        "id": "CRYPTO-002",
        "name": "Weak Password Storage Pattern",
        "category": "Weak Password Storage",
        "severity": "CRITICAL",
        "cwe": "CWE-916",
        "patterns": [
            r"password.*hashlib\.(md5|sha1|sha256)\(",
            r"hashlib\.(md5|sha1|sha256)\(.*\bpassword",
            r"pbkdf2.*iterations\s*=\s*([1-9][0-9]{0,3}|[1-9][0-9]{4})\b",  # < 100,000 iterations
            r"createHash\([^)]+\).*\bpassword",
            r"MessageDigest\.getInstance\([^)]+\).*\bpassword",
        ],
        "description": "General-purpose hash algorithm or insufficient PBKDF2 iterations used for password storage without slow key stretching.",
        "remediation": "Use specialized password hashing algorithms: Argon2id (recommended), bcrypt (cost >= 12), or PBKDF2-HMAC-SHA256 with >= 600,000 iterations.",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html", "CWE-916"]
    },
    {
        "id": "CRYPTO-003",
        "name": "Hardcoded Secret / Private Key",
        "category": "Hardcoded Secrets",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "patterns": [
            r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----",
            r"(secret_key|jwt_secret|api_key|private_key)\s*=\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"]",
            r"const\s+(SECRET|JWT_SECRET|API_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{8,}['\"]",
            r"String\s+(SECRET|PRIVATE_KEY)\s*=\s*\"[^\"]{8,}\"",
        ],
        "description": "Hardcoded cryptographic key, private key, or authentication secret detected in source code.",
        "remediation": "Store keys in environment variables, secure key vaults (e.g. AWS KMS, HashiCorp Vault), or hardware security modules (HSM).",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"]
    },
    {
        "id": "CRYPTO-004",
        "name": "Insecure Pseudo-Random Number Generation (PRNG)",
        "category": "Insecure Randomness",
        "severity": "HIGH",
        "cwe": "CWE-330",
        "patterns": [
            r"\b(random\.random|random\.randint|random\.choice)\s*\(",
            r"\bMath\.random\s*\(\)",
            r"\brand\(\)",
            r"new\s+java\.util\.Random\s*\(",
            r"math/rand",
        ],
        "description": "Standard non-cryptographic PRNG used in code. Output can be predicted if seed or state is observed.",
        "remediation": "Use Cryptographically Secure Pseudo-Random Number Generators (CSPRNG): `secrets` module in Python, `crypto.getRandomValues()` / `crypto.randomBytes()` in JS/Node, `java.security.SecureRandom` in Java.",
        "references": ["https://cwe.mitre.org/data/definitions/330.html", "NIST SP 800-90A"]
    },
    {
        "id": "CRYPTO-005",
        "name": "Insecure Symmetric Cipher Mode (ECB Mode)",
        "category": "Weak Symmetric Encryption",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "patterns": [
            r"AES\.MODE_ECB",
            r"Cipher\.getInstance\(\s*['\"]AES/ECB/",
            r"Cipher\.getInstance\(\s*['\"]DES",
            r"createCipheriv\(\s*['\"]aes-[0-9]+-ecb",
            r"MODE_ECB",
            r"DES/ECB",
        ],
        "description": "AES or DES in Electronic Codebook (ECB) mode detected. ECB mode does not provide pattern confidentiality (identical plaintext blocks yield identical ciphertext blocks).",
        "remediation": "Use authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305. If GCM is unavailable, use AES-CBC with HMAC (Encrypt-then-MAC).",
        "references": ["https://cwe.mitre.org/data/definitions/327.html"]
    },
    {
        "id": "CRYPTO-006",
        "name": "Weak / Insecure Cipher Algorithm & Key Size",
        "category": "Insecure Key Sizes & Weak Ciphers",
        "severity": "HIGH",
        "cwe": "CWE-326",
        "patterns": [
            r"\b(DES|3DES|TripleDES|RC4|Blowfish)\b",
            r"KeyPairGenerator\.getInstance\([^)]+\).*\b(512|1024)\b",
            r"rsa\.generate_private_key\([^)]*key_size\s*=\s*(512|1024)",
            r"generateKeyPair\([^)]*modulusLength\s*:\s*(512|1024)",
            r"aes-128-ecb|des-ede3",
        ],
        "description": "Legacy weak cipher (DES, RC4, 3DES) or insufficient RSA key size (< 2048 bits) detected.",
        "remediation": "Use AES-256 or AES-128 in GCM mode. For RSA asymmetric keys, use minimum key length of 2048 bits (3072+ bits recommended) or ECC (Ed25519 / NIST P-256).",
        "references": ["https://cwe.mitre.org/data/definitions/326.html", "NIST SP 800-57"]
    },
    {
        "id": "CRYPTO-007",
        "name": "Deprecated Cryptographic API Usage",
        "category": "Deprecated Cryptographic APIs",
        "severity": "MEDIUM",
        "cwe": "CWE-477",
        "patterns": [
            r"Crypto\.Cipher\.XOR",
            r"mcrypt_",
            r"ssl\.PROTOCOL_TLSv1(_[0-1])?",
            r"SSLv23_method|TLSv1_method",
            r"crypto\.createCipher\(",  # Node.js deprecated createCipher without IV
        ],
        "description": "Deprecated cryptographic library call or TLS protocol version detected.",
        "remediation": "Upgrade to modern supported crypto primitives (e.g. `pyca/cryptography` in Python, modern Web Crypto API / Node `crypto.createCipheriv`, TLS 1.2 / TLS 1.3).",
        "references": ["https://cwe.mitre.org/data/definitions/477.html"]
    },
    {
        "id": "CRYPTO-008",
        "name": "Hardcoded Symmetric Key / Fixed IV",
        "category": "Hardcoded Encryption Keys",
        "severity": "HIGH",
        "cwe": "CWE-321",
        "patterns": [
            r"AES\.new\(\s*b['\"][^'\"]{1,32}['\"]",
            r"new\s+SecretKeySpec\(\s*['\"][^'\"]+['\"]\.getBytes\(",
            r"iv\s*=\s*b?['\"][00]{8,16}['\"]",
            r"createCipheriv\([^,]+,\s*['\"][^'\"]+['\"],\s*['\"][0-9a-fA-F]{16,32}['\"]",
            r"IV\s*=\s*new\s+byte\[\]\s*\{0,\s*0,\s*0",
        ],
        "description": "Hardcoded encryption key or static/reused Initialization Vector (IV) detected.",
        "remediation": "Generate a unique, cryptographically random IV for every encryption operation using CSPRNG. Load encryption keys dynamically from key management systems.",
        "references": ["https://cwe.mitre.org/data/definitions/321.html"]
    },
    {
        "id": "CRYPTO-009",
        "name": "Weak / Insecure TLS & SSL Certificate Validation",
        "category": "Weak TLS & Certificate Problems",
        "severity": "HIGH",
        "cwe": "CWE-295",
        "patterns": [
            r"ssl\._create_unverified_context",
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"TrustAllManager|ALLOW_ALL_HOSTNAME_VERIFIER",
            r"InsecureSkipVerify\s*:\s*true",
            r"check_hostname\s*=\s*False",
        ],
        "description": "TLS certificate validation or hostname verification is explicitly disabled, enabling Man-In-The-Middle (MITM) attacks.",
        "remediation": "Enable strict TLS certificate validation. Use trusted CA certificate stores and hostname verification.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"]
    },
    {
        "id": "CRYPTO-010",
        "name": "Insecure JWT Configuration",
        "category": "Insecure JWT Configurations",
        "severity": "CRITICAL",
        "cwe": "CWE-347",
        "patterns": [
            r"alg['\"]?\s*:\s*['\"]none['\"]",
            r"jwt\.decode\([^)]*verify\s*=\s*False",
            r"jwt\.decode\([^)]*verify_signature\s*=\s*False",
            r"algorithms\s*=\s*\[\s*['\"]none['\"]\s*\]",
            r"options\s*:\s*\{\s*verify_signature\s*:\s*false",
        ],
        "description": "JSON Web Token (JWT) allows 'none' signature algorithm or signature verification is turned off.",
        "remediation": "Enforce signature verification. Explicitly whitelist strong algorithms (e.g. HS256, RS256, ES256) and reject tokens signed with 'none'.",
        "references": ["https://cwe.mitre.org/data/definitions/347.html", "RFC 7519"]
    }
]

def compile_rules():
    """Compiles regex patterns into regex objects for performance."""
    compiled = []
    for rule in RULES:
        rule_copy = dict(rule)
        rule_copy["compiled_patterns"] = [
            re.compile(p, re.IGNORECASE) for p in rule["patterns"]
        ]
        compiled.append(rule_copy)
    return compiled
