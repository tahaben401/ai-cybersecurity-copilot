"""
MANTIS AI Service — Schemas Package.

Schémas Pydantic pour la validation et sérialisation des données:
    - sarif_schema: Données SARIF entrantes (depuis scan.results)
    - patch_schema: Résultats AI sortants (vers ai.results)
"""
from app.schemas.sarif_schema import Finding, ScanResultMessage, SeverityLevel
from app.schemas.patch_schema import (
    AIAnalysisResult,
    AIBatchResult,
    EnrichmentData,
    PatchStatus,
    PatchSuggestion,
    ReviewResult,
    VulnerabilityAnalysis,
)

__all__ = [
    # Input schemas
    "Finding",
    "ScanResultMessage",
    "SeverityLevel",
    # Output schemas
    "AIAnalysisResult",
    "AIBatchResult",
    "EnrichmentData",
    "PatchStatus",
    "PatchSuggestion",
    "ReviewResult",
    "VulnerabilityAnalysis",
]
