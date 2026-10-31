"""
Configuration settings for the LLM Code Analyzer.
Loads settings from environment variables with sensible defaults.
"""

import os
from typing import Literal, Optional
from dotenv import load_dotenv
from pydantic import BaseModel

load_dotenv()


class Settings(BaseModel):
    """Application settings."""
    
    # LLM Mode: openai, gemini, or ollama
    llm_mode: Literal["openai", "gemini", "ollama"] = os.getenv("LLM_MODE", "gemini")
    
    # OpenAI Configuration
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    # Google Gemini Configuration
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    
    # Ollama Configuration (for offline mode)
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "codellama")
    
    # Server Configuration
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Analysis Configuration
    max_code_length: int = int(os.getenv("MAX_CODE_LENGTH", "50000"))
    analysis_timeout: int = int(os.getenv("ANALYSIS_TIMEOUT", "120"))
    
    # Rate Limiting Configuration
    analysis_requests_per_minute: int = int(os.getenv("RATE_LIMIT_ANALYSIS_PER_MINUTE", "60"))
    redis_url: Optional[str] = os.getenv("REDIS_URL", "")


settings = Settings()
