"""
Canonical CWE Normalizer and Classification Engine.
Fulfills FR-3: One common finding format with canonical CWE numbers,
supporting Semgrep, AST, and DAST (OWASP ZAP, Nuclei, SARIF) findings.
"""

import re
import os
import hashlib
from typing import Dict, Any, Tuple, Optional, List, Union, Set


# ---------------------------------------------------------------------------
# Canonical CWE Definitions & Metadata
# ---------------------------------------------------------------------------

CANONICAL_CWE_METADATA: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "cwe_id": "CWE-89",
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "default_remediation": "Use parameterized queries or ORM abstractions instead of direct string concatenation or formatting."
    },
    "CWE-79": {
        "cwe_id": "CWE-79",
        "name": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "default_remediation": "Contextually encode user-controlled input before rendering it in HTML or template contexts."
    },
    "CWE-22": {
        "cwe_id": "CWE-22",
        "name": "Path Traversal",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "default_remediation": "Resolve absolute paths and verify they reside within the designated safe root directory."
    },
    "CWE-78": {
        "cwe_id": "CWE-78",
        "name": "OS Command Injection",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "default_remediation": "Avoid invoking shell interpreters (shell=False) and pass discrete argument vectors without shell metacharacters."
    },
    "CWE-798": {
        "cwe_id": "CWE-798",
        "name": "Hard-coded Credentials",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Use of Hard-coded Credentials or Cryptographic Secrets",
        "default_remediation": "Extract secrets into secure environment variables, vault management systems, or secrets stores."
    },
    "CWE-328": {
        "cwe_id": "CWE-328",
        "name": "Weak Hashing / Broken Cryptography",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Use of Weak Hash or Broken Cryptographic Algorithm",
        "default_remediation": "Migrate to modern cryptographic primitives such as SHA-256, SHA-3, or Argon2/bcrypt for passwords."
    },
    "CWE-918": {
        "cwe_id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Server-Side Request Forgery (SSRF)",
        "default_remediation": "Validate target URLs against a strict allowlist and restrict network egress from server instances."
    },
    "CWE-601": {
        "cwe_id": "CWE-601",
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "URL Redirection to Untrusted Site ('Open Redirect')",
        "default_remediation": "Validate redirect targets against an approved relative path or domain allowlist."
    },
    "CWE-693": {
        "cwe_id": "CWE-693",
        "name": "Missing Security Headers / Protection Mechanism Failure",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Protection Mechanism Failure: The application does not use or incorrectly configures critical defense headers (e.g. CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
        "default_remediation": "Configure defensive HTTP response headers including Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options."
    },
    "CWE-16": {
        "cwe_id": "CWE-16",
        "name": "Security Misconfiguration",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Configuration weakness or insecure default settings exposing the application to attack.",
        "default_remediation": "Review server and framework configuration settings and apply secure baselines."
    },
    "CWE-200": {
        "cwe_id": "CWE-200",
        "name": "Information Exposure",
        "severity": "LOW",
        "confidence": "HIGH",
        "description": "Information Exposure: The application inadvertently discloses sensitive system, environment, or component information in HTTP headers or responses.",
        "default_remediation": "Suppress server banners, remove debugging tokens, and standardize error responses."
    },
    "CWE-209": {
        "cwe_id": "CWE-209",
        "name": "Sensitive Data Exposure via Debug Mode",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Generation of Error Message Containing Sensitive Information: Diagnostic or debug stack trace page exposed.",
        "default_remediation": "Disable DEBUG mode in production environments and use a custom generic 500 error handler."
    },
    "CWE-502": {
        "cwe_id": "CWE-502",
        "name": "Insecure Deserialization",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Deserialization of Untrusted Data",
        "default_remediation": "Avoid untrusted deserialization formats (e.g. pickle, yaml.load) and use safe parsers like json or yaml.safe_load."
    },
    "CWE-94": {
        "cwe_id": "CWE-94",
        "name": "Code Injection",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Improper Control of Generation of Code ('Code Injection')",
        "default_remediation": "Avoid dynamic code execution (eval, exec); use structured data parsing instead."
    },
    "CWE-352": {
        "cwe_id": "CWE-352",
        "name": "Cross-Site Request Forgery (CSRF)",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Cross-Site Request Forgery (CSRF)",
        "default_remediation": "Enforce anti-CSRF tokens and SameSite cookie attributes on state-changing endpoints."
    },
    "CWE-611": {
        "cwe_id": "CWE-611",
        "name": "XML External Entity (XXE) Injection",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Improper Restriction of XML External Entity Reference",
        "default_remediation": "Disable external entity resolution (DTD/XInclude) in all XML parsers."
    },
    "CWE-862": {
        "cwe_id": "CWE-862",
        "name": "Broken Access Control / Missing Authorization",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Missing Authorization: The application does not perform authorization checks for functionality access.",
        "default_remediation": "Implement role-based access control (RBAC) and verify user permissions on all protected routes."
    },
    "CWE-639": {
        "cwe_id": "CWE-639",
        "name": "Insecure Direct Object Reference (IDOR)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Authorization Bypass Through User-Controlled Key (IDOR): Access to records granted without verifying object ownership.",
        "default_remediation": "Validate that the currently authenticated user owns or has explicit permission to access the requested object ID."
    },
    "CWE-287": {
        "cwe_id": "CWE-287",
        "name": "Improper Authentication / Broken Session",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Improper Authentication: Mechanisms for verifying identity or session credentials are weak or bypassed.",
        "default_remediation": "Use secure session management libraries, enforce MFA, and protect authentication tokens."
    },
    "CWE-204": {
        "cwe_id": "CWE-204",
        "name": "Observable Response Discrepancy (Credential Enumeration)",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Response discrepancy allows an attacker to enumerate valid usernames or account identifiers.",
        "default_remediation": "Return uniform authentication failure messages and enforce constant-time credential checks."
    },
    "CWE-614": {
        "cwe_id": "CWE-614",
        "name": "Insecure Cookie",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Sensitive Cookie in HTTPS Session Without 'Secure' or 'HttpOnly' Attribute.",
        "default_remediation": "Ensure all sensitive and authentication cookies include Secure, HttpOnly, and SameSite attributes."
    },
    "CWE-915": {
        "cwe_id": "CWE-915",
        "name": "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Mass Assignment: The software modifies object attributes from user input without restricting writable fields.",
        "default_remediation": "Use explicit DTOs, schemas, or allowlists for bindable model attributes."
    },
    "CWE-1336": {
        "cwe_id": "CWE-1336",
        "name": "Server-Side Template Injection (SSTI)",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Improper Neutralization of Special Elements in Template Engine (SSTI)",
        "default_remediation": "Do not render untrusted user input directly as template strings; use static template files and pass variables via context."
    },
    "CWE-117": {
        "cwe_id": "CWE-117",
        "name": "Improper Output Neutralization for Logs (Log Injection)",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": "Improper Output Neutralization for Logs: Unsanitized user input written to log files can forge log entries or inject malicious control characters.",
        "default_remediation": "Sanitize user input before writing to logs by stripping newline and carriage return characters."
    }
}


# ---------------------------------------------------------------------------
# Canonical CWE Equivalence Groups
# ---------------------------------------------------------------------------

CWE_EQUIVALENCE_GROUPS: Dict[str, Set[str]] = {
    "CWE-89": {"CWE-89", "CWE-564", "CWE-943"},
    "CWE-79": {"CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-1336"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "CWE-78": {"CWE-78", "CWE-77", "CWE-88"},
    "CWE-94": {"CWE-94", "CWE-95", "CWE-96", "CWE-1336"},
    "CWE-1336": {"CWE-1336", "CWE-94", "CWE-95", "CWE-79"},
    "CWE-502": {"CWE-502"},
    "CWE-601": {"CWE-601"},
    "CWE-918": {"CWE-918"},
    "CWE-798": {"CWE-798", "CWE-259", "CWE-321"},
    "CWE-328": {"CWE-328", "CWE-327", "CWE-329", "CWE-354", "CWE-916"},
    "CWE-200": {"CWE-200", "CWE-209", "CWE-256", "CWE-312", "CWE-359", "CWE-522"},
    "CWE-862": {"CWE-862", "CWE-284", "CWE-285", "CWE-306"},
    "CWE-639": {"CWE-639", "CWE-862", "CWE-284"},
    "CWE-287": {"CWE-287", "CWE-345", "CWE-384", "CWE-640"},
    "CWE-204": {"CWE-204", "CWE-203"},
    "CWE-614": {"CWE-614", "CWE-1004"},
    "CWE-352": {"CWE-352"},
    "CWE-915": {"CWE-915"},
    "CWE-693": {"CWE-693", "CWE-16", "CWE-1032"},
    "CWE-611": {"CWE-611", "CWE-827"},
    "CWE-117": {"CWE-117", "CWE-93", "CWE-116"},
}


# ---------------------------------------------------------------------------
# Mapping Child / Variant CWEs to Canonical Form
# ---------------------------------------------------------------------------

CWE_VARIANT_MAP: Dict[str, str] = {
    # SQL Injection variants -> CWE-89
    "CWE-89": "CWE-89",
    "89": "CWE-89",
    "CWE-564": "CWE-89",   # Hibernate SQL injection
    "564": "CWE-89",
    "CWE-943": "CWE-89",   # Special elements in data query logic
    "943": "CWE-89",
    "CWE-20": "CWE-89",    # In context of SQL input validation

    # XSS variants -> CWE-79
    "CWE-79": "CWE-79",
    "79": "CWE-79",
    "CWE-80": "CWE-79",    # Basic XSS
    "80": "CWE-79",
    "CWE-81": "CWE-79",
    "81": "CWE-79",
    "CWE-82": "CWE-79",
    "82": "CWE-79",
    "CWE-83": "CWE-79",
    "83": "CWE-79",
    "CWE-84": "CWE-79",
    "84": "CWE-79",
    "CWE-85": "CWE-79",
    "85": "CWE-79",
    "CWE-86": "CWE-79",
    "86": "CWE-79",
    "CWE-87": "CWE-79",
    "87": "CWE-79",
    "CWE-116": "CWE-79",   # Improper Encoding/Escaping
    "116": "CWE-79",

    # Path Traversal variants -> CWE-22
    "CWE-22": "CWE-22",
    "22": "CWE-22",
    "CWE-23": "CWE-22",    # Relative Path Traversal
    "23": "CWE-22",
    "CWE-35": "CWE-22",    # Path Traversal: '.../...//'
    "35": "CWE-22",
    "CWE-36": "CWE-22",    # Absolute Path Traversal
    "36": "CWE-22",
    "CWE-73": "CWE-22",    # External Control of File Name or Path
    "73": "CWE-22",
    "CWE-99": "CWE-22",    # Resource Injection
    "99": "CWE-22",

    # Command Injection variants -> CWE-78
    "CWE-78": "CWE-78",
    "78": "CWE-78",
    "CWE-77": "CWE-78",    # Command Injection
    "77": "CWE-78",
    "CWE-88": "CWE-78",    # Argument Injection
    "88": "CWE-78",

    # Hard-coded Credentials -> CWE-798
    "CWE-798": "CWE-798",
    "798": "CWE-798",
    "CWE-259": "CWE-798",  # Hard-coded Password
    "259": "CWE-798",
    "CWE-321": "CWE-798",  # Hard-coded Cryptographic Key
    "321": "CWE-798",
    "CWE-547": "CWE-798",  # Hardcoded Security Constants
    "547": "CWE-798",

    # Weak Hashing / Broken Crypto -> CWE-328
    "CWE-328": "CWE-328",
    "328": "CWE-328",
    "CWE-327": "CWE-328",  # Broken or Risky Crypto Algorithm
    "327": "CWE-328",
    "CWE-329": "CWE-328",  # Not Using a Random IV with CBC Mode
    "329": "CWE-328",
    "CWE-354": "CWE-328",  # Improper Validation of Integrity Check
    "354": "CWE-328",
    "CWE-326": "CWE-328",  # Inadequate Encryption Strength
    "326": "CWE-328",
    "CWE-916": "CWE-328",  # Password Hash with Insufficient Computational Effort
    "916": "CWE-328",
    "CWE-330": "CWE-328",  # Use of Insufficiently Random Values
    "330": "CWE-328",
    "CWE-338": "CWE-328",  # Weak PRNG
    "338": "CWE-328",

    # Insecure Deserialization -> CWE-502
    "CWE-502": "CWE-502",
    "502": "CWE-502",
    "CWE-503": "CWE-502",

    # Code Injection -> CWE-94
    "CWE-94": "CWE-94",
    "94": "CWE-94",
    "CWE-95": "CWE-94",    # Eval Injection
    "95": "CWE-94",
    "CWE-96": "CWE-94",    # Static Code Injection
    "96": "CWE-94",

    # Server-Side Template Injection (SSTI) -> CWE-1336
    "CWE-1336": "CWE-1336",
    "1336": "CWE-1336",

    # Log Injection / Improper Output Neutralization for Logs -> CWE-117
    "CWE-117": "CWE-117",
    "117": "CWE-117",
    "CWE-93": "CWE-117",

    # XXE -> CWE-611
    "CWE-611": "CWE-611",
    "611": "CWE-611",
    "CWE-827": "CWE-611",

    # SSRF -> CWE-918
    "CWE-918": "CWE-918",
    "918": "CWE-918",

    # Open Redirect -> CWE-601
    "CWE-601": "CWE-601",
    "601": "CWE-601",

    # Broken Access Control -> CWE-862
    "CWE-862": "CWE-862",
    "862": "CWE-862",
    "CWE-284": "CWE-862",  # Improper Access Control
    "284": "CWE-862",
    "CWE-285": "CWE-862",  # Improper Authorization
    "285": "CWE-862",
    "CWE-306": "CWE-862",  # Missing Authentication for Critical Function
    "306": "CWE-862",

    # IDOR -> CWE-639
    "CWE-639": "CWE-639",
    "639": "CWE-639",

    # Broken Authentication / Session -> CWE-287
    "CWE-287": "CWE-287",
    "287": "CWE-287",
    "CWE-345": "CWE-287",
    "345": "CWE-287",
    "CWE-384": "CWE-287",  # Session Fixation
    "384": "CWE-287",
    "CWE-640": "CWE-287",  # Weak Password Recovery Mechanism
    "640": "CWE-287",

    # Credential Enumeration -> CWE-204
    "CWE-204": "CWE-204",
    "204": "CWE-204",
    "CWE-203": "CWE-204",
    "203": "CWE-204",

    # Insecure Cookie -> CWE-614
    "CWE-614": "CWE-614",
    "614": "CWE-614",
    "CWE-1004": "CWE-614", # Sensitive Cookie Without 'HttpOnly' Flag
    "1004": "CWE-614",

    # Missing Security Headers / Protection Failure -> CWE-693
    "CWE-693": "CWE-693",
    "693": "CWE-693",
    "CWE-1021": "CWE-693", # Restriction of Rendered UI (Clickjacking)
    "1021": "CWE-693",
    "CWE-319": "CWE-693",  # Cleartext Transmission (Missing HSTS)
    "319": "CWE-693",
    "CWE-16": "CWE-693",   # Configuration Weakness
    "16": "CWE-693",
    "CWE-1032": "CWE-693", # Security Misconfiguration
    "1032": "CWE-693",
    "CWE-942": "CWE-693",  # Permissive CORS Policy
    "942": "CWE-693",

    # Sensitive Data Exposure via Debug Mode -> CWE-209
    "CWE-209": "CWE-209",
    "209": "CWE-209",

    # Information Exposure -> CWE-200
    "CWE-200": "CWE-200",
    "200": "CWE-200",
    "CWE-256": "CWE-200",  # Plaintext Storage of Password
    "256": "CWE-200",
    "CWE-312": "CWE-200",  # Cleartext Storage of Sensitive Information
    "312": "CWE-200",
    "CWE-359": "CWE-200",  # Exposure of Private Personal Information
    "359": "CWE-200",
    "CWE-522": "CWE-200",  # Insufficiently Protected Credentials
    "522": "CWE-200",

    # CSRF -> CWE-352
    "CWE-352": "CWE-352",
    "352": "CWE-352",
    "CWE-1275": "CWE-352", # Sensitive Cookie Without 'SameSite' Attribute
    "1275": "CWE-352",

    # Mass Assignment -> CWE-915
    "CWE-915": "CWE-915",
    "915": "CWE-915",

    # XXE -> CWE-611
    "CWE-611": "CWE-611",
    "611": "CWE-611",
}


# ---------------------------------------------------------------------------
# OWASP ZAP Plugin ID to Canonical CWE Mapping
# ---------------------------------------------------------------------------

ZAP_PLUGIN_TO_CWE: Dict[str, str] = {
    # SQL Injection
    "40018": "CWE-89",   # SQL Injection
    "40019": "CWE-89",   # SQL Injection - MySQL
    "40020": "CWE-89",   # SQL Injection - Hypersonic
    "40021": "CWE-89",   # SQL Injection - Oracle
    "40022": "CWE-89",   # SQL Injection - PostgreSQL
    "40024": "CWE-89",   # SQL Injection - SQLite
    "40027": "CWE-89",   # SQL Injection - MsSQL
    "90018": "CWE-89",   # Advanced SQL Injection

    # Cross-Site Scripting (XSS)
    "40012": "CWE-79",   # Reflected XSS
    "40014": "CWE-79",   # Persistent / Stored XSS
    "40016": "CWE-79",   # Persistent XSS - Prime
    "40017": "CWE-79",   # Persistent XSS - Spider
    "10104": "CWE-79",   # User Controllable HTML Element Attribute (XSS)

    # Path Traversal
    "6": "CWE-22",       # Path Traversal
    "7": "CWE-22",       # Remote File Inclusion
    "40003": "CWE-22",   # Path Traversal / CR-LF Path Manipulation

    # OS Command Injection
    "90020": "CWE-78",   # Remote OS Command Injection
    "90019": "CWE-78",   # Server Side Code Execution / Command Injection

    # Code Injection
    "90021": "CWE-94",   # XPath / Code Injection

    # XXE
    "90023": "CWE-611",  # XML External Entity (XXE)

    # Open Redirect
    "10028": "CWE-601",  # Open Redirect
    "20019": "CWE-601",  # External Redirect
    "40028": "CWE-601",  # Open Redirect (Active)

    # SSRF
    "40046": "CWE-918",  # Server-Side Request Forgery (SSRF)

    # Insecure Cookie
    "10010": "CWE-614",  # Cookie No HttpOnly Flag
    "10011": "CWE-614",  # Cookie Without Secure Flag
    "10054": "CWE-614",  # Cookie Without SameSite Attribute

    # CSRF
    "10202": "CWE-352",  # Absence of Anti-CSRF Tokens

    # Missing Security Headers / Protection Mechanism Failure
    "10038": "CWE-693",  # Content Security Policy (CSP) Header Not Set
    "10020": "CWE-693",  # X-Frame-Options Header Missing (Clickjacking)
    "10021": "CWE-693",  # X-Content-Type-Options Header Missing
    "10035": "CWE-693",  # Strict-Transport-Security Header Not Set (HSTS)
    "10098": "CWE-693",  # Cross-Domain Misconfiguration
    "10049": "CWE-693",  # Content-Security-Policy (CSP) Missing
    "10055": "CWE-693",  # CSP: Wildcard Directive
    "10016": "CWE-693",  # Web Browser XSS Protection Not Enabled
    "10017": "CWE-693",  # Cross-Domain Misconfiguration

    # Sensitive Data Exposure / Error Messages
    "90022": "CWE-209",  # Application Error Disclosure / Debug Information Leak
    "10056": "CWE-209",  # X-Debug-Token Information Leak
    "10096": "CWE-200",  # Timestamp Disclosure
    "10027": "CWE-200",  # Information Disclosure - Suspicious Comments
    "10037": "CWE-200",  # Server Leaks Information via "Server" Header
    "2": "CWE-200",      # Private IP Disclosure
    "3": "CWE-287",      # Session ID in URL Rewrite
}

# Alias for backwards compatibility
ZAP_PLUGIN_MAP = ZAP_PLUGIN_TO_CWE


# ---------------------------------------------------------------------------
# Heuristic Keyword Fallback (for Semgrep rule IDs / Scanner message tags)
# ---------------------------------------------------------------------------

KEYWORD_TO_CANONICAL_CWE: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(sql[_-]?injection|sqli|sqlalchemy|cursor\.execute|raw[_-]?sql)', re.IGNORECASE), "CWE-89"),
    (re.compile(r'(cross[_-]?site[_-]?scripting|xss|innerhtml|document\.write|dangerouslysetinnerhtml)', re.IGNORECASE), "CWE-79"),
    (re.compile(r'(path[_-]?traversal|directory[_-]?traversal|local[_-]?file[_-]?inclusion|lfi|fileresponse|send_file)', re.IGNORECASE), "CWE-22"),
    (re.compile(r'(command[_-]?injection|os[_-]?command|shell[_-]?injection|os\.system|subprocess|execsync)', re.IGNORECASE), "CWE-78"),
    (re.compile(r'(hardcoded[_-]?secret|hardcoded[_-]?password|hardcoded[_-]?credential|api[_-]?key|jwt[_-]?secret|private[_-]?key)', re.IGNORECASE), "CWE-798"),
    (re.compile(r'(weak[_-]?(crypto|hash|algorithm)|broken[_-]?crypto|md5|sha1|des[_-]?cipher|rc4)', re.IGNORECASE), "CWE-328"),
    (re.compile(r'(ssrf|server[_-]?side[_-]?request[_-]?forgery)', re.IGNORECASE), "CWE-918"),
    (re.compile(r'(open[_-]?redirect|untrusted[_-]?redirect)', re.IGNORECASE), "CWE-601"),
    (re.compile(r'(content[_-]?security[_-]?policy|csp|x[_-]?frame[_-]?options|strict[_-]?transport|hsts|x[_-]?content[_-]?type|security[_-]?header|clickjacking)', re.IGNORECASE), "CWE-693"),
    (re.compile(r'(insecure[_-]?deserialization|pickle|unpickler|yaml\.load)', re.IGNORECASE), "CWE-502"),
    (re.compile(r'(template[_-]?injection|ssti|render_template_string|jinja2\.template)', re.IGNORECASE), "CWE-1336"),
    (re.compile(r'(log[_-]?injection|crlf[_-]?log|improper[_-]?output[_-]?neutralization.*log)', re.IGNORECASE), "CWE-117"),
    (re.compile(r'(code[_-]?injection|dangerous[_-]?(eval|exec))', re.IGNORECASE), "CWE-94"),
    (re.compile(r'(information[_-]?disclosure|information[_-]?exposure|server[_-]?header|timestamp[_-]?disclosure)', re.IGNORECASE), "CWE-200"),
    (re.compile(r'(csrf|cross[_-]?site[_-]?request)', re.IGNORECASE), "CWE-352"),
    (re.compile(r'(xxe|xml[_-]?external[_-]?entity)', re.IGNORECASE), "CWE-611"),
    (re.compile(r'(broken[_-]?access|missing[_-]?auth|unauthorized|rbac)', re.IGNORECASE), "CWE-862"),
    (re.compile(r'(idor|insecure[_-]?direct[_-]?object)', re.IGNORECASE), "CWE-639"),
    (re.compile(r'(broken[_-]?auth|session[_-]?fixation|credential[_-]?stuffing)', re.IGNORECASE), "CWE-287"),
    (re.compile(r'(user[_-]?enumeration|credential[_-]?enumeration)', re.IGNORECASE), "CWE-204"),
    (re.compile(r'(insecure[_-]?cookie|cookie[_-]?(httponly|secure|samesite))', re.IGNORECASE), "CWE-614"),
    (re.compile(r'(mass[_-]?assignment|object[_-]?injection|parameter[_-]?binding)', re.IGNORECASE), "CWE-915"),
    (re.compile(r'(debug[_-]?mode|stack[_-]?trace|traceback)', re.IGNORECASE), "CWE-209"),
]


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}


def extract_cwe_string(raw: Any) -> Optional[str]:
    """Extract standard 'CWE-XYZ' format from string, list, or dict."""
    if not raw:
        return None
    if isinstance(raw, list):
        for item in raw:
            found = extract_cwe_string(item)
            if found:
                return found
        return None

    text = str(raw).strip()
    if text in ("-1", "0", "null", "none"):
        return None

    match = re.search(r'\bCWE[-_]?(\d+)\b', text, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    if text.isdigit() and text not in ("0", "-1"):
        return f"CWE-{text}"
    return None


def are_cwes_equivalent(cwe_a: Optional[str], cwe_b: Optional[str]) -> bool:
    """
    Checks if two CWE identifiers are identical, canonical equivalents,
    or belong to the same CWE equivalence group family.
    """
    if not cwe_a or not cwe_b:
        return False

    norm_a = extract_cwe_string(cwe_a) or str(cwe_a).strip().upper()
    norm_b = extract_cwe_string(cwe_b) or str(cwe_b).strip().upper()

    if norm_a == norm_b:
        return True

    canon_a = CWE_VARIANT_MAP.get(norm_a, norm_a)
    canon_b = CWE_VARIANT_MAP.get(norm_b, norm_b)
    if canon_a == canon_b and canon_a:
        return True

    for group in CWE_EQUIVALENCE_GROUPS.values():
        if (norm_a in group or canon_a in group) and (norm_b in group or canon_b in group):
            return True

    return False


def normalize_cwe(
    raw_cwe: Optional[Union[str, List[Any], int]] = None,
    rule_name: Optional[str] = None,
    message: Optional[str] = None,
    plugin_id: Optional[Union[str, int]] = None
) -> Tuple[str, str, str, str]:
    """
    Deterministically normalizes any input CWE representation, ZAP plugin ID,
    or scanner rule name to our canonical CWE ID, vulnerability type name, severity, and description.

    Returns:
        (cwe_id, vulnerability_type, severity, description)
    """
    canonical = None

    # Step 1: Check ZAP pluginId if provided
    if plugin_id:
        p_str = str(plugin_id).strip()
        if p_str in ZAP_PLUGIN_TO_CWE:
            canonical = ZAP_PLUGIN_TO_CWE[p_str]

    # Step 2: Check raw CWE ID
    if not canonical:
        extracted = extract_cwe_string(raw_cwe)
        if extracted and extracted in CWE_VARIANT_MAP:
            canonical = CWE_VARIANT_MAP[extracted]

    # Step 3: Check rule_name as pluginId
    if not canonical and rule_name:
        r_str = str(rule_name).strip()
        if r_str in ZAP_PLUGIN_TO_CWE:
            canonical = ZAP_PLUGIN_TO_CWE[r_str]

    # Step 4: Search corpus (rule_name + message + raw_cwe) for explicit CWE or keywords
    if not canonical:
        corpus = f"{rule_name or ''} {message or ''} {raw_cwe or ''}"
        text_cwe = extract_cwe_string(corpus)
        if text_cwe and text_cwe in CWE_VARIANT_MAP:
            canonical = CWE_VARIANT_MAP[text_cwe]
        else:
            for pattern, cwe_target in KEYWORD_TO_CANONICAL_CWE:
                if pattern.search(corpus):
                    canonical = cwe_target
                    break

    # Fallback default
    if not canonical:
        canonical = "CWE-693" if ("header" in (message or "").lower() or "missing" in (message or "").lower()) else "CWE-89"

    meta = CANONICAL_CWE_METADATA.get(canonical, {
        "cwe_id": canonical,
        "name": rule_name or "Security Vulnerability",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "description": message or f"Vulnerability mapped to {canonical}",
        "default_remediation": "Apply standard defensive coding practices."
    })

    return (
        meta["cwe_id"],
        meta["name"],
        meta["severity"],
        meta.get("description", "")
    )


def compute_dast_dedup_key(
    http_method: str,
    url_path: str,
    parameter: Optional[str],
    cwe_id: str
) -> str:
    """
    Computes a deterministic SHA256 fingerprint for DAST findings (FR-6):
    hash of f"DAST:{http_method}:{url_path}:{parameter}:{cwe_id}".
    """
    method_norm = (http_method or "GET").strip().upper()
    url_norm = (url_path or "/").strip()
    param_norm = (parameter or "").strip()
    cwe_norm = (cwe_id or "").strip().upper()

    raw_signature = f"DAST:{method_norm}:{url_norm}:{param_norm}:{cwe_norm}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


def compute_dedup_key(
    source_scanner: str,
    file_path: Optional[str],
    line: Optional[int],
    cwe_id: str
) -> str:
    """
    Computes a deterministic SHA256 fingerprint for SAST findings (FR-3 / FR-6).
    """
    scanner_type = (source_scanner or "SAST").strip().upper()
    norm_file = os.path.normpath(file_path or "").replace("\\", "/")
    if norm_file.startswith("./"):
        norm_file = norm_file[2:]

    line_str = str(line or 0)
    cwe_norm = (cwe_id or "").strip().upper()

    raw_signature = f"{scanner_type}:{norm_file}:{line_str}:{cwe_norm}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()
