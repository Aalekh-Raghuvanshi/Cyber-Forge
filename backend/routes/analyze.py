"""
API routes for code analysis endpoints.
Includes Phase 1 deterministic SAST scan and AST route mapping endpoints.
"""

import os
import uuid
import tempfile
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form

from backend.models.schemas import (
    AnalysisRequest, AnalysisResponse, HealthResponse,
    MultiFileAnalysisRequest, MultiFileAnalysisResponse, FileAnalysisResult,
    SASTScanRequest, SASTScanResponse, RouteEntry,
    DASTScanRequest, DASTScanResponse
)
from backend.services.analyzer import get_analyzer_service
from backend.services.llm_service import get_llm_service
from backend.services.sast_scanner import get_sast_scanner_service
from backend.services.dast_scanner import get_dast_scanner
from backend.services.route_mapper import extract_routes_from_folder
from backend.config import settings
from backend.utils.rate_limit import get_rate_limit_remaining, update_rate_limit, limiter
from backend.utils.logger import get_logger, set_correlation_id

logger = get_logger("analyze_routes")

router = APIRouter()


# ---------------------------------------------------------------------------
# Phase 1: SAST Scan & AST Route Mapping Endpoints (FR-1, FR-3, FR-4)
# ---------------------------------------------------------------------------

@router.post("/sast/scan", response_model=SASTScanResponse)
@limiter.limit(f"{settings.analysis_requests_per_minute} per minute")
async def sast_scan(
    request: Request,
    request_data: SASTScanRequest
) -> SASTScanResponse:
    """
    Deterministic Primary SAST Scanner Endpoint (FR-1, FR-3, FR-4).
    
    - Executes Semgrep CLI paired with AST & Regex fallback scanner.
    - Zero-Hallucination: line numbers, CWEs, and detection are 100% deterministic.
    - Deterministically maps findings to Canonical CWEs (CWE-89, CWE-79, CWE-22, CWE-78, CWE-798, CWE-328).
    - Extracts the AST Route Map and enriches findings with their enclosing route handler & URL path.
    - Deduplicates findings via deterministic SHA256 dedup_key.
    """
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    set_correlation_id(correlation_id)

    scanner = get_sast_scanner_service()

    if request_data.source_folder:
        folder = request_data.source_folder
        if not os.path.exists(folder):
            raise HTTPException(status_code=400, detail=f"Source folder does not exist: {folder}")
        logger.info("Starting SAST folder scan", folder=folder, correlation_id=correlation_id)
        result = scanner.scan_folder(folder, generate_fixes=request_data.generate_fixes or False)
        return result

    elif request_data.files:
        logger.info(f"Starting SAST scan on {len(request_data.files)} uploaded files", correlation_id=correlation_id)
        result = scanner.scan_files(request_data.files, generate_fixes=request_data.generate_fixes or False)
        return result

    else:
        raise HTTPException(
            status_code=400,
            detail="Must provide either 'source_folder' or 'files' in request body."
        )


@router.post("/sast/scan-upload", response_model=SASTScanResponse)
@limiter.limit(f"{settings.analysis_requests_per_minute} per minute")
async def sast_scan_upload(
    request: Request,
    uploaded_files: List[UploadFile] = File(...),
    generate_fixes: bool = Form(default=False)
) -> SASTScanResponse:
    """
    Multipart file upload endpoint for scanning multi-file packages or project directories.
    """
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    set_correlation_id(correlation_id)

    if not uploaded_files:
        raise HTTPException(status_code=400, detail="No files were uploaded.")

    scanner = get_sast_scanner_service()
    files_payload = []

    for f in uploaded_files:
        content_bytes = await f.read()
        content_str = content_bytes.decode("utf-8", errors="replace")
        files_payload.append({
            "filename": f.filename or "uploaded_file.py",
            "content": content_str
        })

    logger.info(f"Scanning {len(files_payload)} uploaded files via multipart form", correlation_id=correlation_id)
    return scanner.scan_files(files_payload, generate_fixes=generate_fixes)


@router.get("/sast/routes", response_model=List[RouteEntry])
async def get_route_map(source_folder: str = ".") -> List[RouteEntry]:
    """
    FR-4 Route Map inspection endpoint.
    Extracts all FastAPI, Flask, and Express route entries with exact handler functions and line ranges.
    """
    if not os.path.exists(source_folder):
        raise HTTPException(status_code=400, detail=f"Directory '{source_folder}' does not exist.")

    routes = extract_routes_from_folder(source_folder)
    return routes


# ---------------------------------------------------------------------------
# Phase 2: DAST Scanner & OWASP ZAP Ingestion Endpoint (FR-2, FR-3, FR-6)
# ---------------------------------------------------------------------------

@router.post("/dast/scan", response_model=DASTScanResponse)
@limiter.limit(f"{settings.analysis_requests_per_minute} per minute")
async def dast_scan(
    request: Request,
    request_data: DASTScanRequest
) -> DASTScanResponse:
    """
    DAST Scanner Endpoint (FR-2, FR-3, FR-6).
    
    - Executes live OWASP ZAP API scan or ingests pre-captured reports / local verification.
    - Captures url_path, http_method, parameter, payload, and evidence.
    - Normalizes alerts to canonical CWEs with 'Runtime only' status label.
    - Idempotent deduplication via SHA256 of DAST:http_method:url_path:parameter:cwe_id.
    """
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
    set_correlation_id(correlation_id)

    if not request_data.target_url or not request_data.target_url.strip():
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    logger.info("Starting DAST scan", target_url=request_data.target_url, correlation_id=correlation_id)
    scanner = get_dast_scanner()
    result = scanner.scan(request_data)
    return result


# ---------------------------------------------------------------------------
# Legacy Endpoints (Maintained for Backward Compatibility)
# ---------------------------------------------------------------------------

@router.post("/analyze", response_model=AnalysisResponse)
@limiter.limit(f"{settings.analysis_requests_per_minute} per minute")
async def analyze_code(request: Request, request_data: AnalysisRequest) -> AnalysisResponse:
    """
    Analyze source code for security vulnerabilities.
    
    This endpoint performs comprehensive security analysis using:
    - Static analysis for pattern-based vulnerability detection
    - LLM analysis for semantic understanding and complex vulnerabilities
    
    Returns attack surfaces, trust boundaries, vulnerabilities, and fix suggestions.
    """
    # Get client IP and correlation ID
    client_ip = request.client.host if request.client else "unknown"
    correlation_id = request.headers.get("X-Correlation-ID", None)
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
    
    set_correlation_id(correlation_id)
    
    if not request_data.code or not request_data.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty")
    
    if len(request_data.code) > settings.max_code_length:
        raise HTTPException(
            status_code=400, 
            detail=f"Code exceeds maximum length of {settings.max_code_length} characters"
        )
    
    logger.info(
        "Starting code analysis",
        correlation_id=correlation_id,
        client_ip=client_ip,
        language=request_data.language or "auto"
    )
    
    update_rate_limit(client_ip)
    
    analyzer = get_analyzer_service()
    result = await analyzer.analyze_code(
        code=request_data.code,
        language=request_data.language or "auto",
        context=request_data.context
    )
    
    if result.success:
        logger.info(
            "Analysis completed successfully",
            correlation_id=correlation_id,
            client_ip=client_ip,
            language=result.language,
            risk_score=result.risk_score,
            vulnerabilities_count=len(result.vulnerabilities)
        )
    else:
        logger.error(
            "Analysis failed",
            correlation_id=correlation_id,
            client_ip=client_ip,
            error=result.error
        )
    
    return result


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Check the health status of the analyzer service.
    
    Returns the current status, LLM mode, and version information.
    """
    llm_service = get_llm_service()
    is_healthy = llm_service.health_check()
    
    return HealthResponse(
        status="healthy" if is_healthy else "degraded",
        llm_mode=settings.llm_mode,
        version="1.0.0"
    )


@router.get("/config")
async def get_config():
    """
    Get current configuration (non-sensitive values only).
    """
    return {
        "llm_mode": settings.llm_mode,
        "model": settings.openai_model if settings.llm_mode == "online" else settings.ollama_model,
        "max_code_length": settings.max_code_length,
        "analysis_timeout": settings.analysis_timeout
    }


@router.post("/analyze-multiple", response_model=MultiFileAnalysisResponse)
async def analyze_multiple_files(request: MultiFileAnalysisRequest) -> MultiFileAnalysisResponse:
    """
    Analyze multiple files for security vulnerabilities.
    
    This endpoint analyzes a batch of files and returns aggregated results.
    Each file is analyzed independently, and results are combined.
    """
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided")
    
    if len(request.files) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 files allowed per request")
    
    analyzer = get_analyzer_service()
    results = []
    total_vulnerabilities = 0
    risk_scores = []
    
    for file_info in request.files:
        filename = file_info.get('filename', 'unknown')
        content = file_info.get('content', '')
        language = file_info.get('language', 'auto')
        
        if not content.strip():
            continue
            
        if len(content) > settings.max_code_length:
            results.append(FileAnalysisResult(
                filename=filename,
                filepath=filename,
                analysis=AnalysisResponse(
                    success=False,
                    language=language,
                    summary=f"File skipped: exceeds maximum length of {settings.max_code_length} characters",
                    risk_score=0,
                    error="File too large"
                )
            ))
            continue
        
        try:
            analysis = await analyzer.analyze_code(
                code=content,
                language=language,
                context=f"File: {filename}"
            )
            results.append(FileAnalysisResult(
                filename=filename,
                filepath=filename,
                analysis=analysis
            ))
            total_vulnerabilities += len(analysis.vulnerabilities)
            if analysis.risk_score > 0:
                risk_scores.append(analysis.risk_score)
        except Exception as e:
            results.append(FileAnalysisResult(
                filename=filename,
                filepath=filename,
                analysis=AnalysisResponse(
                    success=False,
                    language=language,
                    summary=f"Analysis failed: {str(e)}",
                    risk_score=0,
                    error=str(e)
                )
            ))
    
    overall_risk = int(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
    
    return MultiFileAnalysisResponse(
        success=True,
        total_files=len(results),
        total_vulnerabilities=total_vulnerabilities,
        overall_risk_score=overall_risk,
        summary=f"Analyzed {len(results)} files. Found {total_vulnerabilities} vulnerabilities. Overall risk: {overall_risk}/100.",
        results=results
    )
