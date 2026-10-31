"""
Main analyzer service that orchestrates LLM and static analysis.
"""

from typing import Optional, Dict, Any
from backend.services.llm_service import get_llm_service, LLMError
from backend.services.static_analyzer import get_static_analyzer
from backend.utils.prompt_engine import build_analysis_prompt
from backend.models.schemas import AnalysisResponse


class AnalyzerService:
    """Main service for coordinating code security analysis."""
    
    def __init__(self):
        self.llm_service = get_llm_service()
        self.static_analyzer = get_static_analyzer()
    
    async def analyze_code(
        self,
        code: str,
        language: str = "auto",
        context: Optional[str] = None,
        include_static: bool = True
    ) -> AnalysisResponse:
        """
        Perform comprehensive security analysis on code.
        
        Args:
            code: Source code to analyze
            language: Programming language (auto-detect if not specified)
            context: Optional context about the code
            include_static: Whether to include static analysis findings
            
        Returns:
            AnalysisResponse with all findings
        """
        try:
            # Step 1: Run static analysis
            static_findings = []
            if include_static:
                static_findings = self.static_analyzer.analyze(code, language)
            
            # Step 2: Build prompt and call LLM
            prompt = build_analysis_prompt(code, language, static_findings if static_findings else None)
            
            # Add context if provided
            if context:
                prompt = f"Additional context: {context}\n\n{prompt}"
            
            # Step 3: Get LLM analysis
            llm_result = await self.llm_service.analyze(prompt)
            
            # Step 4: Merge and validate results
            return self._build_response(llm_result, static_findings)
            
        except LLMError as e:
            return AnalysisResponse(
                success=False,
                language=language,
                summary="Analysis failed due to LLM error",
                risk_score=0,
                error=str(e)
            )
        except Exception as e:
            return AnalysisResponse(
                success=False,
                language=language,
                summary="Analysis failed due to unexpected error",
                risk_score=0,
                error=str(e)
            )
    
    def _build_response(self, llm_result: Dict[str, Any], static_findings: list) -> AnalysisResponse:
        """Build the analysis response from LLM results and static findings."""
        try:
            # Extract fields with defaults
            vulnerabilities = llm_result.get("vulnerabilities", [])
            attack_surfaces = llm_result.get("attack_surfaces", [])
            trust_boundaries = llm_result.get("trust_boundaries", [])
            
            # Calculate risk score if not provided
            risk_score = llm_result.get("risk_score", self._calculate_risk_score(vulnerabilities))
            
            return AnalysisResponse(
                success=True,
                language=llm_result.get("language", "unknown"),
                summary=llm_result.get("summary", "Analysis completed"),
                risk_score=min(100, max(0, risk_score)),  # Clamp to 0-100
                attack_surfaces=attack_surfaces,
                trust_boundaries=trust_boundaries,
                vulnerabilities=vulnerabilities,
                recommendations=llm_result.get("recommendations", []),
                static_findings=static_findings if static_findings else None
            )
        except Exception as e:
            return AnalysisResponse(
                success=False,
                language="unknown",
                summary="Failed to parse analysis results",
                risk_score=0,
                error=f"Response parsing error: {str(e)}"
            )
    
    def _calculate_risk_score(self, vulnerabilities: list) -> int:
        """Calculate risk score based on vulnerabilities."""
        if not vulnerabilities:
            return 0
        
        severity_weights = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5
        }
        
        total = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "low").lower()
            total += severity_weights.get(severity, 5)
        
        return min(100, total)


# Singleton instance
_analyzer_service: Optional[AnalyzerService] = None


def get_analyzer_service() -> AnalyzerService:
    """Get or create the analyzer service singleton."""
    global _analyzer_service
    if _analyzer_service is None:
        _analyzer_service = AnalyzerService()
    return _analyzer_service
