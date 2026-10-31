"""
LLM Service for interacting with OpenAI, Google Gemini, and Ollama.
Provides unified interface for all LLM modes.
Includes Phase 3 sandboxed remediation generator (temperature=0.0) with deterministic CWE template fallback.
"""

import json
import httpx
from typing import Optional, Tuple, Dict, Any
from openai import OpenAI, OpenAIError

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

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
    """Service for LLM interactions supporting OpenAI, Gemini, and Ollama."""

    def __init__(self):
        self.mode = settings.llm_mode

        if self.mode == "openai":
            if not settings.openai_api_key:
                raise ValueError("OPENAI_API_KEY is required for openai mode")
            self.client = OpenAI(api_key=settings.openai_api_key)
            self.model = settings.openai_model
        elif self.mode == "gemini":
            if not GEMINI_AVAILABLE:
                raise ValueError("google-generativeai package not installed. Run: pip install google-generativeai")
            if not settings.gemini_api_key:
                raise ValueError("GEMINI_API_KEY is required for gemini mode")
            genai.configure(api_key=settings.gemini_api_key)
            self.model = settings.gemini_model
            self.gemini_model = genai.GenerativeModel(self.model)
        elif self.mode == "ollama":
            self.ollama_url = settings.ollama_base_url
            self.model = settings.ollama_model
        else:
            raise ValueError(f"Unknown LLM mode: {self.mode}. Must be 'openai', 'gemini', or 'ollama'")

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
            if self.mode == "openai":
                response = self.client.chat.completions.create(
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

            elif self.mode == "gemini":
                generation_config = genai.GenerationConfig(
                    temperature=0.0,
                    max_output_tokens=1024,
                    response_mime_type="application/json"
                )
                response = await self.gemini_model.generate_content_async(
                    prompt,
                    generation_config=generation_config
                )
                parsed = self._parse_response(response.text)
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
        if self.mode == "openai":
            return await self._analyze_openai(prompt)
        elif self.mode == "gemini":
            return await self._analyze_gemini(prompt)
        else:
            return await self._analyze_ollama(prompt)

    async def _analyze_openai(self, prompt: str) -> dict:
        """Analyze using OpenAI API."""
        try:
            response = self.client.chat.completions.create(
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

        except OpenAIError as e:
            raise LLMError(f"OpenAI API error: {str(e)}")
        except Exception as e:
            raise LLMError(f"Unexpected error during OpenAI analysis: {str(e)}")

    async def _analyze_gemini(self, prompt: str) -> dict:
        """Analyze using Google Gemini API."""
        try:
            generation_config = genai.GenerationConfig(
                temperature=0.1,
                max_output_tokens=4096,
                response_mime_type="application/json"
            )

            response = await self.gemini_model.generate_content_async(
                prompt,
                generation_config=generation_config
            )

            content = response.text
            return self._parse_response(content)

        except Exception as e:
            raise LLMError(f"Gemini API error: {str(e)}")

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
        if self.mode == "openai":
            try:
                self.client.models.list()
                return True
            except Exception:
                return False
        elif self.mode == "gemini":
            try:
                self.gemini_model.generate_content("test", generation_config=genai.GenerationConfig(max_output_tokens=1))
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
