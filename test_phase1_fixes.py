"""Test Phase 1 fixes for LLM Code Analyzer"""

import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.llm_service import LLMService, LLMError
from backend.config import Settings


def test_llm_service_groq_mode():
    """Test LLM service initialization in Groq mode."""
    with patch('backend.services.llm_service.settings') as mock_settings:
        mock_settings.llm_mode = "groq"
        mock_settings.groq_api_key = "test-key"
        mock_settings.groq_model = "llama-3.3-70b-versatile"

        with patch('backend.services.llm_service.Groq') as mock_groq:
            mock_client = MagicMock()
            mock_groq.return_value = mock_client

            service = LLMService()
            assert service.mode == "groq"
            assert service.model == "llama-3.3-70b-versatile"
            assert service.client == mock_client


def test_llm_service_ollama_mode():
    """Test LLM service initialization in Ollama mode."""
    with patch('backend.services.llm_service.settings') as mock_settings:
        mock_settings.llm_mode = "ollama"
        mock_settings.ollama_base_url = "http://localhost:11434"
        mock_settings.ollama_model = "codellama"

        service = LLMService()
        assert service.mode == "ollama"
        assert service.ollama_url == "http://localhost:11434"
        assert service.model == "codellama"


def test_llm_service_invalid_mode():
    """Test LLM service initialization with invalid mode."""
    with patch('backend.services.llm_service.settings') as mock_settings:
        mock_settings.llm_mode = "invalid_mode"

        with pytest.raises(ValueError, match="Unknown LLM mode"):
            LLMService()


def test_settings_validation():
    """Test that settings has all required fields."""
    settings = Settings()

    assert hasattr(settings, 'llm_mode')
    assert hasattr(settings, 'groq_api_key')
    assert hasattr(settings, 'groq_model')
    assert not hasattr(settings, 'openai_api_key')
    assert not hasattr(settings, 'gemini_api_key')
    assert hasattr(settings, 'ollama_base_url')
    assert hasattr(settings, 'ollama_model')
    assert hasattr(settings, 'max_code_length')
    assert hasattr(settings, 'analysis_timeout')
    assert hasattr(settings, 'analysis_requests_per_minute')
    assert hasattr(settings, 'redis_url')


def test_logger_module():
    """Test logger module functionality."""
    from backend.utils.logger import get_logger, set_correlation_id, get_correlation_id

    # Test logger creation
    logger = get_logger('test')
    assert logger.name == 'test'

    # Test correlation ID
    test_id = str(uuid.uuid4())
    set_correlation_id(test_id)
    assert get_correlation_id() == test_id

    # Test log output
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    logger.info("Test message", test_field="value")
    output = sys.stdout.getvalue()
    sys.stdout = old_stdout

    assert "Test message" in output
    assert '"test_field": "value"' in output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
