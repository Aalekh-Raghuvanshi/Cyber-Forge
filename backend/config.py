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
    
    # LLM Mode: groq or ollama
    llm_mode: Literal["groq", "ollama"] = os.getenv("LLM_MODE", "groq")
    
    # Groq Configuration (for online mode)
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    
    # Ollama Configuration (for offline mode)
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "codellama")
    
    # Server Configuration
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8002"))
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    
    # Analysis Configuration
    max_code_length: int = int(os.getenv("MAX_CODE_LENGTH", "50000"))
    analysis_timeout: int = int(os.getenv("ANALYSIS_TIMEOUT", "120"))
    
    # Rate Limiting Configuration
    analysis_requests_per_minute: int = int(os.getenv("RATE_LIMIT_ANALYSIS_PER_MINUTE", "60"))
    redis_url: Optional[str] = os.getenv("REDIS_URL", "")

    # Datadog SAIST Configuration
    datadog_saist_bin: str = os.getenv("DATADOG_SAIST_BIN", "./bin/datadog-saist")
    enable_datadog_saist: bool = os.getenv("ENABLE_DATADOG_SAIST", "true").lower() == "true"


settings = Settings()
