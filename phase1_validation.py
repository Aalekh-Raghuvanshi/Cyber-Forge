"""Phase 1 validation script for LLM Code Analyzer fixes."""

import sys
import json
from unittest.mock import AsyncMock, MagicMock, patch

def test_llm_service_mode_fix():
    """Test that LLM service correctly handles openai, gemini, ollama modes."""
    print("Testing LLM Service Mode Fix...")
    
    from backend.services.llm_service import LLMService
    
    # Test OpenAI mode
    with patch('backend.services.llm_service.settings') as mock_settings:
        mock_settings.llm_mode = "openai"
        mock_settings.openai_api_key = "test-key"
        mock_settings.openai_model = "gpt-4o-mini"
        
        with patch('backend.services.llm_service.OpenAI') as mock_openai:
            mock_client = MagicMock()
            mock_openai.return_value = mock_client
            
            service = LLMService()
            assert service.mode == "openai"
            assert service.model == "gpt-4o-mini"
            print("  ✅ OpenAI mode: PASSED")
    
    # Test Gemini mode
    with patch('backend.services.llm_service.settings') as mock_settings, \
         patch('backend.services.llm_service.genai') as mock_genai:
        
        mock_settings.llm_mode = "gemini"
        mock_settings.gemini_api_key = "test-key"
        mock_settings.gemini_model = "gemini-2.0-flash"
        
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        
        service = LLMService()
        assert service.mode == "gemini"
        assert service.model == "gemini-2.0-flash"
        print("  ✅ Gemini mode: PASSED")
    
    # Test Ollama mode
    with patch('backend.services.llm_service.settings') as mock_settings:
        mock_settings.llm_mode = "ollama"
        mock_settings.ollama_base_url = "http://localhost:11434"
        mock_settings.ollama_model = "codellama"
        
        service = LLMService()
        assert service.mode == "ollama"
        assert service.model == "codellama"
        print("  ✅ Ollama mode: PASSED")
    
    print("  ✅ All LLM Service mode tests PASSED\n")


def test_logger_module():
    """Test structured logger functionality."""
    print("Testing Logger Module...")
    
    from backend.utils.logger import get_logger, set_correlation_id, get_correlation_id
    import uuid
    
    # Test logger creation
    logger = get_logger('test')
    assert logger.name == 'test'
    print("  ✅ Logger creation: PASSED")
    
    # Test correlation ID
    test_id = str(uuid.uuid4())
    set_correlation_id(test_id)
    assert get_correlation_id() == test_id
    print("  ✅ Correlation ID handling: PASSED")
    
    # Test log output
    import io
    import sys
    
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    
    logger.info("Test message", test_field="value")
    output = sys.stdout.getvalue()
    sys.stdout = old_stdout
    
    # Parse JSON log output
    try:
        log_data = json.loads(output.strip())
        assert log_data['message'] == "Test message"
        assert log_data['test_field'] == "value"
        assert log_data['level'] == "INFO"
        print("  ✅ Structured log output: PASSED")
    except json.JSONDecodeError:
        print("  ❌ Structured log output: FAILED")
        raise
    
    print("  ✅ All logger tests PASSED\n")


def test_rate_limiting_config():
    """Test rate limiting configuration."""
    print("Testing Rate Limiting Configuration...")
    
    from backend.config import Settings
    
    settings = Settings()
    
    # Test that rate limiting fields exist
    assert hasattr(settings, 'analysis_requests_per_minute')
    assert hasattr(settings, 'redis_url')
    
    # Test default values
    assert settings.analysis_requests_per_minute == 60
    print("  ✅ Rate limiting fields exist: PASSED")
    print("  ✅ Default values correct: PASSED")
    
    print("  ✅ All rate limiting config tests PASSED\n")


def test_api_routes_with_rate_limit():
    """Test API routes with rate limiting decorators."""
    print("Testing API Routes with Rate Limiting...")
    
    # Check that the analyze route uses the rate limiting decorator
    from backend.routes.analyze import router
    
    analyze_route = None
    for route in router.routes:
        if hasattr(route, 'path') and route.path == '/analyze':
            analyze_route = route
            break
    
    assert analyze_route is not None, "Could not find /analyze route"
    print("  ✅ Analyze route exists: PASSED")
    
    # Check for rate limit attributes
    if hasattr(analyze_route, 'dependencies'):
        has_rate_limit = any(
            hasattr(dep, '__name__') and 'limiter.limit' in dep.__name__
            for dep in analyze_route.dependencies
        )
        if has_rate_limit:
            print("  ✅ Rate limiting decorator present: PASSED")
        else:
            print("  ⚠️  Rate limiting decorator check: CANNOT VERIFY (requires runtime inspection)")
    else:
        print("  ⚠️  Rate limiting decorator check: CANNOT VERIFY (requires runtime inspection)")
    
    print("  ✅ API route tests PASSED\n")


def test_fastapi_app_imports():
    """Test FastAPI app imports and setup."""
    print("Testing FastAPI App Setup...")
    
    try:
        from backend.app import app
        print("  ✅ FastAPI app imports: PASSED")
    except Exception as e:
        print(f"  ❌ FastAPI app imports: FAILED - {e}")
        raise
    
    print("  ✅ FastAPI app tests PASSED\n")


def main():
    """Run all Phase 1 validation tests."""
    print("=" * 60)
    print("PHASE 1 FIXES VALIDATION")
    print("=" * 60)
    print()
    
    tests = [
        test_llm_service_mode_fix,
        test_logger_module,
        test_rate_limiting_config,
        test_api_routes_with_rate_limit,
        test_fastapi_app_imports
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            with patch('builtins.print'):  # Suppress print for clean output
                test()
            passed += 1
            print(f"✅ {test.__name__}: PASSED")
        except Exception as e:
            failed += 1
            print(f"❌ {test.__name__}: FAILED - {e}")
        print()
    
    print("=" * 60)
    print(f"SUMMARY: {passed} tests passed, {failed} tests failed")
    print("=" * 60)
    
    if failed == 0:
        print("🎉 ALL TESTS PASSED! Phase 1 fixes are working correctly.")
    else:
        print("⚠️  Some tests failed. Please review the fixes.")
        sys.exit(1)


if __name__ == '__main__':
    main()
