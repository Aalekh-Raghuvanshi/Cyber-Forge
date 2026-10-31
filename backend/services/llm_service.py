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
        "fixed_code": "# Use parameterized query binding\ncursor.execute('SELECT * FROM table WHERE id = %s', (user_input,))"
    },
    "CWE-79": {
        "fix_suggestion": "Contextually encode user-controlled input before rendering it in HTML or template contexts.",
        "fixed_code": "import html\nsafe_output = html.escape(user_input)"
    },
    "CWE-22": {
        "fix_suggestion": "Validate and canonicalize file paths using os.path.abspath and verify the resolved path remains strictly within the intended directory.",
        "fixed_code": "safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not safe_path.startswith(os.path.abspath(BASE_DIR)):\n    raise PermissionError('Path traversal detected')"
    },
    "CWE-78": {
        "fix_suggestion": "Avoid invoking shell interpreters (shell=False) and pass discrete argument vectors directly to subprocess.",
        "fixed_code": "import subprocess\nsubprocess.run(['command', arg1, arg2], check=True, shell=False)"
    },
    "CWE-798": {
        "fix_suggestion": "Extract secrets into secure environment variables, vault management systems, or secrets stores.",
        "fixed_code": "import os\nAPI_KEY = os.environ.get('API_KEY')"
    },
    "CWE-328": {
        "fix_suggestion": "Migrate to modern cryptographic primitives such as SHA-256 for data integrity or Argon2/bcrypt for passwords.",
        "fixed_code": "import hashlib\nsecure_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()"
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
        "fixed_code": "if target_domain not in ALLOWED_DOMAINS:\n    raise ValueError('Disallowed destination')"
    },
    "CWE-601": {
        "fix_suggestion": "Validate redirect targets against an approved relative path or domain allowlist.",
        "fixed_code": "if not target_url.startswith('/') or target_url.startswith('//'):\n    target_url = '/'"
    },
    "CWE-502": {
        "fix_suggestion": "Avoid untrusted deserialization formats (e.g. pickle, yaml.load) and use safe parsers like json or yaml.safe_load.",
        "fixed_code": "import json\ndata = json.loads(payload)"
    },
    "CWE-94": {
        "fix_suggestion": "Avoid dynamic code execution (eval, exec); use structured data parsing instead.",
        "fixed_code": "import ast\nresult = ast.literal_eval(safe_expression)"
    }
}


def get_deterministic_remediation(
    cwe_id: str,
    vulnerability_type: Optional[str] = None,
    code_snippet: Optional[str] = None,
    payload: Optional[str] = None
) -> Tuple[str, str]:
    """Generates deterministic remediation advice when LLM is offline or disabled."""
    norm_cwe = (cwe_id or "").strip().upper()
    template = DETERMINISTIC_REMEDIATIONS.get(norm_cwe)

    if template:
        suggestion = template["fix_suggestion"]
        code = template["fixed_code"]

        # Contextualize snippet if available
        if code_snippet and "execute" in code_snippet and norm_cwe == "CWE-89":
            code = "# Parameterized query binding:\ncursor.execute('SELECT ... WHERE id = %s', (param,))"
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
