"""
Structured logging utilities for the LLM Code Analyzer.
"""

import json
import os
import uuid
from datetime import datetime
from typing import Optional, Dict, Any


class CorrelationIdMiddleware:
    """Middleware to add correlation ID to all log messages."""

    def __init__(self):
        self.correlation_id = None

    def get_correlation_id(self) -> str:
        if not self.correlation_id:
            self.correlation_id = str(uuid.uuid4())
        return self.correlation_id

    def set_correlation_id(self, correlation_id: Optional[str] = None):
        self.correlation_id = correlation_id or str(uuid.uuid4())


class StructuredLogger:
    """Structured logger with correlation ID support."""

    def __init__(self, name: str):
        self.name = name
        self._correlation_middleware = CorrelationIdMiddleware()
        self._additional_fields = {}

    def set_correlation_id(self, correlation_id: str):
        self._correlation_middleware.set_correlation_id(correlation_id)

    def get_correlation_id(self) -> str:
        return self._correlation_middleware.get_correlation_id()

    def info(self, message: str, **kwargs):
        self._log('info', message, **kwargs)

    def warning(self, message: str, **kwargs):
        self._log('warning', message, **kwargs)

    def error(self, message: str, exception: Optional[Exception] = None, **kwargs):
        kwargs['exception'] = exception
        self._log('error', message, **kwargs)

    def debug(self, message: str, **kwargs):
        self._log('debug', message, **kwargs)

    def _log(self, level: str, message: str, **kwargs):
        structured_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.get_correlation_id(),
            'level': level.upper(),
            'logger_name': self.name,
            'message': message
        }

        structured_data.update(kwargs)

        if 'exception' in kwargs and kwargs['exception']:
            structured_data['exception'] = {
                'type': type(kwargs['exception']).__name__,
                'message': str(kwargs['exception']),
                'traceback': str(kwargs['exception'].__traceback__) if kwargs['exception'].__traceback__ else None
            }

        output = json.dumps(structured_data)
        print(output)


_loggers: Dict[str, StructuredLogger] = {}
_correlation_middleware = CorrelationIdMiddleware()


def get_logger(name: str) -> StructuredLogger:
    if name not in _loggers:
        _loggers[name] = StructuredLogger(name)
    return _loggers[name]


def get_correlation_id() -> str:
    return _correlation_middleware.get_correlation_id()


def set_correlation_id(correlation_id: str):
    _correlation_middleware.set_correlation_id(correlation_id)


def log_api_request(method: str, path: str, status_code: int,
                    duration_ms: int, user_id: Optional[str] = None,
                    ip_address: Optional[str] = None, request_id: Optional[str] = None):
    logger = get_logger("api")
    logger.info(
        "API request",
        method=method,
        path=path,
        status_code=status_code,
        duration_ms=duration_ms,
        user_id=user_id or "N/A",
        ip_address=ip_address or "N/A",
        request_id=request_id or get_correlation_id()
    )


def log_analysis_request(user_id: str, language: str, risk_score: int,
                         vulnerability_count: int, analysis_time_ms: int):
    logger = get_logger("analysis")
    logger.info(
        "Code analysis completed",
        user_id=user_id,
        language=language,
        risk_score=risk_score,
        vulnerability_count=vulnerability_count,
        analysis_time_ms=analysis_time_ms
    )
