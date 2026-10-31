"""
Canonical CWE Normalizer and Classification Engine.
Fulfills FR-3: One common finding format with canonical CWE numbers,
supporting Semgrep, AST, and DAST (OWASP ZAP) findings.
"""

import re
import os
import hashlib
from typing import Dict, Any, Tuple, Optional, List, Union


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
    }
}


# ---------------------------------------------------------------------------
# Mapping Child / Variant CWEs to Canonical Form
# ---------------------------------------------------------------------------

CWE_VARIANT_MAP: Dict[str, str] = {
    # SQL Injection variants -> CWE-89
    "CWE-89": "CWE-89",
    "89": "CWE-89",
    "CWE-564": "CWE-89",   # Hibernate SQL injection
    "CWE-943": "CWE-89",   # Special elements in data query logic
    "CWE-20": "CWE-89",    # In context of SQL input validation

    # XSS variants -> CWE-79
    "CWE-79": "CWE-79",
    "79": "CWE-79",
    "CWE-80": "CWE-79",    # Basic XSS
    "CWE-81": "CWE-79",
    "CWE-82": "CWE-79",
    "CWE-83": "CWE-79",
    "CWE-84": "CWE-79",
    "CWE-85": "CWE-79",
    "CWE-86": "CWE-79",
    "CWE-87": "CWE-79",
    "CWE-116": "CWE-79",   # Improper Encoding/Escaping

    # Path Traversal variants -> CWE-22
    "CWE-22": "CWE-22",
    "22": "CWE-22",
    "CWE-23": "CWE-22",    # Relative Path Traversal
    "CWE-35": "CWE-22",    # Path Traversal: '.../...//'
    "CWE-36": "CWE-22",    # Absolute Path Traversal
    "CWE-73": "CWE-22",    # External Control of File Name or Path
    "CWE-99": "CWE-22",    # Resource Injection

    # Command Injection variants -> CWE-78
    "CWE-78": "CWE-78",
    "78": "CWE-78",
    "CWE-77": "CWE-78",    # Command Injection
    "CWE-88": "CWE-78",    # Argument Injection

    # Hard-coded Credentials -> CWE-798
    "CWE-798": "CWE-798",
    "798": "CWE-798",
    "CWE-259": "CWE-798",  # Hard-coded Password
    "CWE-321": "CWE-798",  # Hard-coded Cryptographic Key
    "CWE-547": "CWE-798",  # Hardcoded Security Constants

    # Weak Hashing / Broken Crypto -> CWE-328
    "CWE-328": "CWE-328",
    "328": "CWE-328",
    "CWE-327": "CWE-328",  # Broken or Risky Crypto Algorithm
    "CWE-326": "CWE-328",  # Inadequate Encryption Strength
    "CWE-916": "CWE-328",  # Password Hash with Insufficient Computational Effort
    "CWE-330": "CWE-328",  # Use of Insufficiently Random Values
    "CWE-338": "CWE-328",  # Weak PRNG

    # Insecure Deserialization -> CWE-502
    "CWE-502": "CWE-502",
    "502": "CWE-502",
    "CWE-503": "CWE-502",

    # Code Injection -> CWE-94
    "CWE-94": "CWE-94",
    "94": "CWE-94",
    "CWE-95": "CWE-94",    # Eval Injection

    # SSRF -> CWE-918
    "CWE-918": "CWE-918",
    "918": "CWE-918",

    # Open Redirect -> CWE-601
    "CWE-601": "CWE-601",
    "601": "CWE-601",

    # Missing Security Headers / Protection Failure -> CWE-693
    "CWE-693": "CWE-693",
    "693": "CWE-693",
    "CWE-1021": "CWE-693", # Restriction of Rendered UI (Clickjacking)
    "1021": "CWE-693",
    "CWE-319": "CWE-693",  # Cleartext Transmission (Missing HSTS)
    "319": "CWE-693",
    "CWE-1004": "CWE-693", # Sensitive Cookie Without 'HttpOnly' Flag
    "1004": "CWE-693",
    "CWE-614": "CWE-693",  # Sensitive Cookie Without 'Secure' Flag
    "614": "CWE-693",
    "CWE-16": "CWE-693",   # Configuration Weakness
    "16": "CWE-693",
    "CWE-942": "CWE-693",  # Permissive CORS Policy
    "942": "CWE-693",

    # Information Exposure -> CWE-200
    "CWE-200": "CWE-200",
    "200": "CWE-200",
    "CWE-209": "CWE-200",  # Generation of Error Message Containing Sensitive Info
    "209": "CWE-209",

    # CSRF -> CWE-352
    "CWE-352": "CWE-352",
    "352": "CWE-352",
    "CWE-1275": "CWE-352", # Sensitive Cookie Without 'SameSite' Attribute
    "1275": "CWE-352",

    # XXE -> CWE-611
    "CWE-611": "CWE-611",
    "611": "CWE-611",
}


# ---------------------------------------------------------------------------
# OWASP ZAP Plugin ID to Canonical CWE Mapping
# ---------------------------------------------------------------------------

ZAP_PLUGIN_MAP: Dict[str, str] = {
    "40018": "CWE-89",   # SQL Injection
    "40019": "CWE-89",   # SQL Injection - MySQL
    "40020": "CWE-89",   # SQL Injection - Hypersonic
    "40021": "CWE-89",   # SQL Injection - Oracle
    "40022": "CWE-89",   # SQL Injection - PostgreSQL
    "40024": "CWE-89",   # SQL Injection - SQLite
    "40027": "CWE-89",   # SQL Injection - MsSQL
    "40012": "CWE-79",   # Reflected XSS
    "40014": "CWE-79",   # Persistent / Stored XSS
    "40016": "CWE-79",   # Persistent XSS - Prime
    "40017": "CWE-79",   # Persistent XSS - Spider
    "40003": "CWE-79",   # CR-LF Injection
    "6": "CWE-22",       # Path Traversal
    "7": "CWE-22",       # Remote File Inclusion
    "90020": "CWE-78",   # Remote OS Command Injection
    "40028": "CWE-601",  # Open Redirect
    "40046": "CWE-918",  # Server-Side Request Forgery (SSRF)
    "10020": "CWE-693",  # X-Frame-Options Header Missing (Clickjacking)
    "10035": "CWE-693",  # Strict-Transport-Security Header Not Set (HSTS)
    "10038": "CWE-693",  # Content Security Policy (CSP) Header Not Set
    "10049": "CWE-693",  # Content-Security-Policy (CSP) Missing
    "10055": "CWE-693",  # CSP: Wildcard Directive
    "10021": "CWE-693",  # X-Content-Type-Options Header Missing
    "10016": "CWE-693",  # Web Browser XSS Protection Not Enabled
    "10010": "CWE-693",  # Cookie No HttpOnly Flag
    "10011": "CWE-693",  # Cookie Without Secure Flag
    "10054": "CWE-352",  # Cookie Without SameSite Attribute
    "10017": "CWE-693",  # Cross-Domain Misconfiguration
    "10096": "CWE-200",  # Timestamp Disclosure
    "10027": "CWE-200",  # Information Disclosure - Suspicious Comments
    "10037": "CWE-200",  # Server Leaks Information via "Server" Header
    "10056": "CWE-200",  # X-Debug-Token Information Leak
    "2": "CWE-200",      # Private IP Disclosure
    "3": "CWE-384",      # Session ID in URL Rewrite
    "90019": "CWE-78",   # Server Side Code Injection
    "90021": "CWE-94",   # XPath Injection
    "90023": "CWE-611",  # XML External Entity (XXE)
}


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
    (re.compile(r'(code[_-]?injection|dangerous[_-]?(eval|exec))', re.IGNORECASE), "CWE-94"),
    (re.compile(r'(information[_-]?disclosure|information[_-]?exposure|server[_-]?header|timestamp[_-]?disclosure)', re.IGNORECASE), "CWE-200"),
    (re.compile(r'(csrf|cross[_-]?site[_-]?request)', re.IGNORECASE), "CWE-352"),
    (re.compile(r'(xxe|xml[_-]?external[_-]?entity)', re.IGNORECASE), "CWE-611"),
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
        if p_str in ZAP_PLUGIN_MAP:
            canonical = ZAP_PLUGIN_MAP[p_str]

    # Step 2: Check raw CWE ID
    if not canonical:
        extracted = extract_cwe_string(raw_cwe)
        if extracted and extracted in CWE_VARIANT_MAP:
            canonical = CWE_VARIANT_MAP[extracted]

    # Step 3: Check rule_name as pluginId
    if not canonical and rule_name:
        r_str = str(rule_name).strip()
        if r_str in ZAP_PLUGIN_MAP:
            canonical = ZAP_PLUGIN_MAP[r_str]

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
