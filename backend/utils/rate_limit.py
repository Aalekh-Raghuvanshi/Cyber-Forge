"""
Rate limiting utilities for the LLM Code Analyzer.
"""

import json
import time
from datetime import datetime
from typing import Dict, Union, Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.utils.logger import get_logger

limiter = Limiter(key_func=get_remote_address)


def setup_rate_limiting(app):
    """Setup rate limiting middleware and error handler."""

    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
        logger = get_logger("rate_limit")
        logger.warning(
            "Rate limit exceeded",
            client_ip=get_remote_address(request),
            endpoint=str(request.url),
            retry_after=exc.detail,
            timestamp=datetime.utcnow().isoformat()
        )

        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "error": "Rate limit exceeded",
                "message": f"Too many requests. Please wait {exc.detail}",
                "retry_after": exc.detail.split()[2] if ' ' in exc.detail else exc.detail
            }
        )

    return limiter


def get_redis_client():
    """Get Redis client if available, otherwise return None."""

    try:
        import redis
        return redis
    except ImportError:
        return None


def get_redis_connection():
    """Get a Redis connection if configured and available."""
    from backend.config import settings

    if not settings.redis_url:
        return None

    try:
        redis = get_redis_client()
        if not redis:
            return None

        client = redis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2
        )

        try:
            client.ping()
            return client
        except Exception:
            return None
    except Exception:
        return None


def update_rate_limit(client_ip: str, window: int = 60, limit: int = 60):
    """Update rate limit counter for a client IP."""

    redis_client = get_redis_connection()
    if not redis_client:
        return

    key = f"rate_limit:{client_ip}"
    now = time.time()
    try:
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, now - window)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window + 10)
        pipe.execute()
    except Exception:
        pass


def get_rate_limit_remaining(client_ip: str, window: int = 60, limit: int = 60) -> Dict[str, Union[int, Optional[float]]]:
    """Get remaining rate limit for a client IP."""

    redis_client = get_redis_connection()
    if not redis_client:
        return {"remaining": limit, "reset": None, "total_limit": limit}

    key = f"rate_limit:{client_ip}"
    try:
        now = time.time()
        redis_client.zremrangebyscore(key, 0, now - window)
        count = redis_client.zcard(key) or 0
        remaining = max(0, limit - count)
        ttl = redis_client.ttl(key)

        return {
            "remaining": remaining,
            "total_limit": limit,
            "reset": now + ttl if ttl else None
        }
    except Exception:
        return {"remaining": limit, "reset": None, "total_limit": limit}


def log_rate_limit_exceeded(client_ip: str, endpoint: str, limit: str):
    """Log rate limit exceeded events."""

    logger = get_logger("rate_limit")
    logger.warning(
        "Rate limit exceeded",
        client_ip=client_ip,
        endpoint=endpoint,
        limit=limit,
        timestamp=datetime.utcnow().isoformat()
    )
