"""
OpenAI-to-Groq reverse proxy endpoint.
Enables datadog-saist (and any OpenAI-compatible CLI or SDK) to use Groq as its LLM backend.

datadog-saist expects an OpenAI-compatible endpoint (--openai-base-url http://127.0.0.1:8000/internal/groq-proxy).
Because datadog-saist enforces specific model flags (e.g. --detection-model openai-gpt5-mini)
and strips 'openai-' to send 'model': 'gpt5-mini', this proxy rewrites the model parameter
to the configured Groq model (e.g. 'llama-3.3-70b-versatile' or 'openai/gpt-oss-120b'),
enforces temperature=0.0, and forwards requests to https://api.groq.com/openai/v1/chat/completions.
"""

from typing import Any, Dict
import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger("groq_proxy")

router = APIRouter()

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


@router.post("/internal/groq-proxy/v1/chat/completions")
@router.post("/v1/chat/completions")
async def chat_completions_proxy(request: Request) -> Response:
    """
    OpenAI-to-Groq adapter endpoint for datadog-saist.
    Accepts OpenAI chat completion requests, remaps model name to Groq model,
    enforces temperature=0.0, and forwards to Groq API using GROQ_API_KEY.
    """
    try:
        body: Dict[str, Any] = await request.json()
    except Exception as e:
        logger.warning(f"Invalid JSON received by Groq proxy: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    incoming_model = body.get("model", "")
    target_model = settings.groq_model

    # Rewrite model name to the supported Groq model
    body["model"] = target_model

    # Force temperature=0.0 for deterministic, reproducible security analysis
    body["temperature"] = 0.0

    # Ensure max_tokens has a sensible default if not set
    if "max_tokens" not in body or not body["max_tokens"]:
        body["max_tokens"] = 2048

    # Extract API key (prefer environment setting, fallback to Authorization header)
    api_key = settings.groq_api_key
    if not api_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            api_key = auth_header.replace("Bearer ", "").strip()

    if not api_key:
        logger.error("Groq proxy invoked without GROQ_API_KEY configured")
        raise HTTPException(
            status_code=401,
            detail="Missing GROQ_API_KEY. Set GROQ_API_KEY in .env or pass Authorization header."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    logger.info(
        f"Proxying chat completion to Groq: mapped '{incoming_model}' -> '{target_model}' "
        f"(messages={len(body.get('messages', []))})"
    )

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            res = await client.post(
                f"{GROQ_BASE_URL}/chat/completions",
                headers=headers,
                json=body
            )

            # Return the exact upstream response with same status and content
            return Response(
                content=res.content,
                status_code=res.status_code,
                media_type="application/json"
            )
        except httpx.TimeoutException:
            logger.error("Upstream Groq API timed out")
            raise HTTPException(status_code=504, detail="Upstream Groq API timeout (60s)")
        except Exception as e:
            logger.error(f"Error communicating with Groq upstream: {e}")
            raise HTTPException(status_code=502, detail=f"Groq upstream proxy error: {str(e)}")


@router.get("/internal/groq-proxy/v1/models")
@router.get("/v1/models")
async def list_models() -> Dict[str, Any]:
    """
    OpenAI-compatible models list endpoint.
    Advertises both the virtual datadog-saist models and the underlying Groq model.
    """
    return {
        "object": "list",
        "data": [
            {
                "id": "openai-gpt5-mini",
                "object": "model",
                "created": 1700000000,
                "owned_by": "datadog-saist-adapter"
            },
            {
                "id": "gpt5-mini",
                "object": "model",
                "created": 1700000000,
                "owned_by": "datadog-saist-adapter"
            },
            {
                "id": settings.groq_model,
                "object": "model",
                "created": 1700000000,
                "owned_by": "groq"
            }
        ]
    }
