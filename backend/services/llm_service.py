"""
LLM Service for interacting with Groq and Ollama.
Provides unified interface for all LLM modes.
Includes Phase 3 sandboxed remediation generator (temperature=0.0) with deterministic CWE template fallback.
"""

import json
import asyncio
import httpx
from typing import Optional, Tuple, Dict, Any

try:
    from groq import Groq, GroqError
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from backend.config import settings
from backend.utils.prompt_engine import build_remediation_prompt
from backend.utils.logger import get_logger

logger = get_logger("llm_service")


# ---------------------------------------------------------------------------
# Deterministic Fallback Templates per Canonical CWE (FR-5 / FR-9 Sandbox)
# ---------------------------------------------------------------------------

DETERMINISTIC_REMEDIATIONS: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "fix_suggestion": "Use parameterized queries or ORM abstractions instead of direct string concatenation or formatting.",
        "fixed_code": "cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))"
    },
    "CWE-79": {
        "fix_suggestion": "Contextually encode user-controlled input before rendering it in HTML or template contexts.",
        "fixed_code": "from markupsafe import escape\nsafe_output = escape(user_input)"
    },
    "CWE-22": {
        "fix_suggestion": "Validate and canonicalize file paths using os.path.realpath and verify the resolved path remains strictly within the intended directory.",
        "fixed_code": "import os\nsafe_path = os.path.realpath(os.path.join(BASE_DIR, os.path.basename(user_filename)))\nif not safe_path.startswith(os.path.realpath(BASE_DIR)):\n    raise PermissionError('Path traversal detected')"
    },
    "CWE-78": {
        "fix_suggestion": "Avoid invoking shell interpreters (shell=False) and pass discrete argument vectors directly to subprocess.",
        "fixed_code": "import subprocess\nsubprocess.run(['nslookup', domain], check=True, shell=False)"
    },
    "CWE-798": {
        "fix_suggestion": "Extract secrets into secure environment variables, vault management systems, or secrets stores.",
        "fixed_code": "import os\nAPI_KEY = os.environ.get('API_KEY')"
    },
    "CWE-328": {
        "fix_suggestion": "Use a slow, salted key-derivation function such as bcrypt or Argon2 (or werkzeug.security.generate_password_hash) instead of MD5/SHA-1.",
        "fixed_code": "import bcrypt\nhashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())"
    },
    "CWE-693": {
        "fix_suggestion": "Configure defensive HTTP response headers including Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options.",
        "fixed_code": "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\nresponse.headers['X-Frame-Options'] = 'DENY'\nresponse.headers['X-Content-Type-Options'] = 'nosniff'"
    },
    "CWE-200": {
        "fix_suggestion": "Suppress server banners, remove debugging tokens, and standardize error responses to prevent information leakage.",
        "fixed_code": "response.headers.pop('Server', None)"
    },
    "CWE-918": {
        "fix_suggestion": "Validate target URLs against a strict allowlist and restrict network egress from server instances.",
        "fixed_code": "from urllib.parse import urlparse\nparsed = urlparse(target_url)\nif parsed.hostname not in ALLOWED_HOSTS:\n    raise ValueError('Disallowed host')"
    },
    "CWE-601": {
        "fix_suggestion": "Validate redirect targets against an approved relative path or domain allowlist.",
        "fixed_code": "if not target_url.startswith('/') or target_url.startswith('//'):\n    target_url = '/'"
    },
    "CWE-502": {
        "fix_suggestion": "Replace untrusted pickle deserialization with safe serialization formats like JSON and verify payload integrity with HMAC.",
        "fixed_code": "import json\ndata = json.loads(raw_payload)"
    },
    "CWE-94": {
        "fix_suggestion": "Avoid dynamic code execution (eval, exec); use structured data parsing instead.",
        "fixed_code": "import ast\nresult = ast.literal_eval(user_expression)"
    },
    "CWE-1336": {
        "fix_suggestion": "Do not render untrusted user input directly as template strings; use static template files and pass variables via context.",
        "fixed_code": "from flask import render_template\nreturn render_template('blog.html', content=user_content)"
    },
    "CWE-611": {
        "fix_suggestion": "Disable external entity resolution (DTD/XInclude) or use safe XML libraries like defusedxml.",
        "fixed_code": "from defusedxml.ElementTree import fromstring\nxml_doc = fromstring(xml_payload)"
    },
    "CWE-117": {
        "fix_suggestion": "Sanitize user input before writing to logs by stripping newline and carriage return characters.",
        "fixed_code": "import re\nsafe_msg = re.sub(r'[\\r\\n]', '', user_input)\nlogger.info(safe_msg)"
    },
    "CWE-209": {
        "fix_suggestion": "Disable DEBUG mode in production environments to avoid leaking stack traces and environment data.",
        "fixed_code": "DEBUG = False"
    },
    "CWE-862": {
        "fix_suggestion": "Enforce server-side authorization checks based on authenticated user sessions rather than trusting client cookies or headers.",
        "fixed_code": "if not request.user.is_authenticated or not request.user.has_perm('app.view'):\n    raise PermissionDenied()"
    },
    "CWE-287": {
        "fix_suggestion": "Verify user authentication using secure server-side session stores instead of unverified headers or cookies.",
        "fixed_code": "if not authenticate_session(request.session):\n    return redirect('/login')"
    },
    "CWE-90": {
        "fix_suggestion": "Sanitize and escape user input using ldap3.utils.conv.escape_filter_chars or ldap.filter.escape_filter_chars before interpolating into LDAP queries.",
        "fixed_code": "import ldap3.utils.conv\nsafe_val = ldap3.utils.conv.escape_filter_chars(user_input)\nfilter_str = f'(&(objectclass=person)(uid={safe_val}))'"
    },
    "CWE-327": {
        "fix_suggestion": "Replace broken or legacy cryptographic algorithms (DES, Blowfish, RC4) with strong, modern ciphers like AES-GCM or ChaCha20-Poly1305 via the cryptography library.",
        "fixed_code": "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\naesgcm = AESGCM(key)\nencrypted_data = aesgcm.encrypt(nonce, data, None)"
    },
    "CWE-330": {
        "fix_suggestion": "Use the cryptographically secure standard library module `secrets` (or `random.SystemRandom()`) instead of standard pseudo-random functions like `random.random()` or `random.randint()` for security-sensitive tokens, cookies, or salts.",
        "fixed_code": "import secrets\nsecure_token = secrets.token_urlsafe(32)"
    },
    "CWE-501": {
        "fix_suggestion": "Validate, sanitize, and verify user authorization before saving client-supplied keys or data directly into server-side session stores.",
        "fixed_code": "if user_input in ALLOWED_SESSION_KEYS:\n    session[user_input] = validated_value"
    },
    "CWE-643": {
        "fix_suggestion": "Use parameterized XPath variables or escape special XPath characters (e.g., replace single quotes with '&apos;') rather than string concatenating user input into XPath expressions.",
        "fixed_code": "nodes = root.xpath('/Employees/Employee[@emplid=$id]', id=user_id)"
    },
    "CWE-614": {
        "fix_suggestion": "Ensure all sensitive and authentication cookies include Secure, HttpOnly, and SameSite attributes.",
        "fixed_code": "response.set_cookie('session_id', token, secure=True, httponly=True, samesite='Lax')"
    }
}


def get_deterministic_remediation(
    cwe_id: str,
    vulnerability_type: Optional[str] = None,
    code_snippet: Optional[str] = None,
    payload: Optional[str] = None
) -> Tuple[str, str]:
    """Generates context-aware deterministic Python remediation advice when LLM is offline or disabled."""
    norm_cwe = (cwe_id or "").strip().upper()

    # Context-Sensitive CWE-502 (YAML vs. Pickle)
    if norm_cwe == "CWE-502":
        snippet_lower = (code_snippet or "").lower()
        if "yaml" in snippet_lower:
            return (
                "Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution during YAML parsing.",
                "import yaml\ndata = yaml.safe_load(user_yaml_input)"
            )
        else:
            return (
                "Replace untrusted pickle deserialization with safe serialization formats like JSON and verify payload integrity with HMAC.",
                "import json\ndata = json.loads(raw_payload)"
            )

    template = DETERMINISTIC_REMEDIATIONS.get(norm_cwe)

    if template:
        suggestion = template["fix_suggestion"]
        code = template["fixed_code"]
        return (suggestion, code)

    return (
        f"Apply defensive programming practices to address {vulnerability_type or norm_cwe}.",
        "# Ensure user inputs are strictly validated and parameterized"
    )


class LLMService:
    """Service for LLM interactions supporting Groq and Ollama."""

    def __init__(self):
        self.mode = settings.llm_mode

        if self.mode == "groq":
            if not GROQ_AVAILABLE:
                raise ValueError("groq package not installed. Run: pip install groq")
            if not settings.groq_api_key:
                raise ValueError("GROQ_API_KEY is required for groq mode")
            self.client = Groq(api_key=settings.groq_api_key)
            self.model = settings.groq_model
        elif self.mode == "ollama":
            self.ollama_url = settings.ollama_base_url
            self.model = settings.ollama_model
        else:
            raise ValueError(f"Unknown LLM mode: {self.mode}. Must be 'groq' or 'ollama'")

    async def generate_remediation(
        self,
        cwe_id: str,
        vulnerability_type: str,
        file: Optional[str] = None,
        line: Optional[int] = None,
        code_snippet: Optional[str] = None,
        payload: Optional[str] = None,
        evidence: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Sandboxed LLM Remediation (Strictly temperature=0.0).
        Generates fix_suggestion and fixed_code for already deterministically correlated issues.
        Falls back seamlessly to deterministic templates if offline or error occurs.
        """
        # Build prompt
        prompt = build_remediation_prompt(
            cwe_id=cwe_id,
            vulnerability_type=vulnerability_type,
            file=file,
            line=line,
            code_snippet=code_snippet,
            payload=payload,
            evidence=evidence
        )

        try:
            if self.mode == "groq":
                parsed = None
                if self.client:
                    try:
                        response = await asyncio.to_thread(
                            self.client.chat.completions.create,
                            model=self.model,
                            messages=[
                                {
                                    "role": "system",
                                    "content": "You are a secure code remediation assistant. Output valid JSON strictly with fix_suggestion and fixed_code."
                                },
                                {"role": "user", "content": prompt}
                            ],
                            temperature=0.0,
                            max_tokens=1024,
                            response_format={"type": "json_object"}
                        )
                        parsed = self._parse_response(response.choices[0].message.content)
                    except Exception as client_err:
                        logger.debug(f"Groq SDK client error, trying direct HTTP fallback: {client_err}")

                # Direct HTTP Groq fallback via https://api.groq.com/openai/v1
                if not parsed and settings.groq_api_key:
                    async with httpx.AsyncClient(timeout=15.0) as http_client:
                        http_res = await http_client.post(
                            "https://api.groq.com/openai/v1/chat/completions",
                            headers={
                                "Authorization": f"Bearer {settings.groq_api_key}",
                                "Content-Type": "application/json"
                            },
                            json={
                                "model": self.model,
                                "messages": [
                                    {
                                        "role": "system",
                                        "content": "You are a secure code remediation assistant. Output valid JSON strictly with fix_suggestion and fixed_code."
                                    },
                                    {"role": "user", "content": prompt}
                                ],
                                "temperature": 0.0,
                                "max_tokens": 1024,
                                "response_format": {"type": "json_object"}
                            }
                        )
                        if http_res.status_code == 200:
                            content = http_res.json()["choices"][0]["message"]["content"]
                            parsed = self._parse_response(content)

                if parsed:
                    suggestion = parsed.get("fix_suggestion")
                    fixed_code = parsed.get("fixed_code")
                    if suggestion and fixed_code:
                        return (suggestion, fixed_code)

            elif self.mode == "ollama":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.post(
                        f"{self.ollama_url}/api/generate",
                        json={
                            "model": self.model,
                            "prompt": prompt,
                            "stream": False,
                            "format": "json",
                            "options": {"temperature": 0.0}
                        }
                    )
                    if response.status_code == 200:
                        parsed = self._parse_response(response.json().get("response", ""))
                        suggestion = parsed.get("fix_suggestion")
                        fixed_code = parsed.get("fixed_code")
                        if suggestion and fixed_code:
                            return (suggestion, fixed_code)

        except Exception as e:
            logger.debug(f"LLM remediation generation used deterministic fallback ({e})")

        # Fallback to deterministic template
        return get_deterministic_remediation(
            cwe_id=cwe_id,
            vulnerability_type=vulnerability_type,
            code_snippet=code_snippet,
            payload=payload
        )

    async def analyze(self, prompt: str) -> dict:
        """Send legacy prompt to LLM and get structured response."""
        if self.mode == "groq":
            return await self._analyze_groq(prompt)
        else:
            return await self._analyze_ollama(prompt)

    async def _analyze_groq(self, prompt: str) -> dict:
        """Analyze using Groq API."""
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert analyzing code for vulnerabilities. Always respond with valid JSON only."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=4096,
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            return self._parse_response(content)

        except GroqError as e:
            raise LLMError(f"Groq API error: {str(e)}")
        except Exception as e:
            raise LLMError(f"Unexpected error during Groq analysis: {str(e)}")

    async def _analyze_ollama(self, prompt: str) -> dict:
        """Analyze using Ollama local model."""
        try:
            async with httpx.AsyncClient(timeout=settings.analysis_timeout) as client:
                response = await client.post(
                    f"{self.ollama_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                response.raise_for_status()

                result = response.json()
                content = result.get("response", "")
                return self._parse_response(content)

        except httpx.TimeoutException:
            raise LLMError("Ollama request timed out. The model may be loading or the code is too complex.")
        except httpx.HTTPError as e:
            raise LLMError(f"Ollama API error: {str(e)}")
        except Exception as e:
            raise LLMError(f"Unexpected error during Ollama analysis: {str(e)}")

    def _parse_response(self, content: str) -> dict:
        """Parse LLM response into structured dict."""
        try:
            content = content.strip()
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(lines[1:-1])

            return json.loads(content)
        except json.JSONDecodeError as e:
            raise LLMError(f"Failed to parse LLM response as JSON: {str(e)}\nResponse: {content[:500]}")

    def health_check(self) -> bool:
        """Check if the LLM service is available."""
        if self.mode == "groq":
            try:
                self.client.models.list()
                return True
            except Exception:
                return False
        else:
            try:
                import httpx
                response = httpx.get(f"{self.ollama_url}/api/tags", timeout=5)
                return response.status_code == 200
            except Exception:
                return False


class LLMError(Exception):
    """Custom exception for LLM-related errors."""
    pass


_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """Get or create the LLM service singleton."""
    global _llm_service
    if _llm_service is None:
        try:
            _llm_service = LLMService()
        except Exception as e:
            logger.debug(f"LLMService init warning ({e}); fallback mode will be used.")
            return None
    return _llm_service
