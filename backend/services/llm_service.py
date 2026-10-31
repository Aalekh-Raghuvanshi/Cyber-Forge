"""
LLM Service for interacting with OpenAI, Google Gemini, and Ollama.
Provides unified interface for all LLM modes.
"""

import json
import httpx
from typing import Optional
from openai import OpenAI, OpenAIError

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

from backend.config import settings


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

    async def analyze(self, prompt: str) -> dict:
        """
        Send prompt to LLM and get structured response.

        Args:
            prompt: The analysis prompt with code

        Returns:
            Parsed JSON response from LLM
        """
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
            # Configure generation settings
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

            # Handle potential markdown code blocks
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
                # Try a simple generation to check connectivity
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


# Singleton instance
_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """Get or create the LLM service singleton."""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service