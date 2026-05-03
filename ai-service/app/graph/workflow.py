"""
MANTIS AI Service — Workflow LangGraph.

C'est ici que tout se connecte. Le workflow définit le graphe orienté
qui orchestre les 4 agents dans le bon ordre, avec la boucle
conditionnelle Coder↔Reviewer.

Architecture du Graphe:
    ┌─────────┐     ┌──────────┐     ┌────────┐     ┌──────────┐
    │ Analyst │────▶│ Enricher │────▶│ Coder  │────▶│ Reviewer │
    └─────────┘     └──────────┘     └────────┘     └────┬─────┘
                                        ▲                │
                                        │   rejected     │
                                        └────────────────┘
                                        (max N retries)
                                                         │ approved / max retries
                                                         ▼
                                                       [END]

Usage:
    from app.graph.workflow import process_finding

    result = await process_finding(finding_dict, scan_id, project_id)
    # result est un AIAnalysisResult prêt à envoyer via RabbitMQ
"""
import time
from langgraph.graph import StateGraph, END

from app.graph.state import MantisState
from app.graph.nodes.analyst import analyst_node
from app.graph.nodes.enricher import enricher_node
from app.graph.nodes.coder import coder_node
from app.graph.nodes.reviewer import reviewer_node
from app.schemas.patch_schema import (
    AIAnalysisResult,
    VulnerabilityAnalysis,
    EnrichmentData,
    PatchSuggestion,
    ReviewResult,
)
from app.core.logger import logger
from app.core.config import settings


# ── Fonction de routage conditionnel ─────────────────────────────────

def route_after_reviewer(state: MantisState) -> str:
    """
    Décide quoi faire après le Reviewer :
        - "coder" → retry (patch rejeté + retries restants)
        - "end"   → terminé (approuvé ou retries épuisés)
    """
    current = state.get("current_agent", "done")
    if current == "coder":
        return "coder"
    return "end"


# ── Construction du Graphe ───────────────────────────────────────────

def build_workflow() -> StateGraph:
    """
    Construit le graphe LangGraph avec les 4 agents.

    Returns:
        StateGraph compilé prêt à être invoqué.
    """
    graph = StateGraph(MantisState)

    # Ajouter les noeuds
    graph.add_node("analyst", analyst_node)
    graph.add_node("enricher", enricher_node)
    graph.add_node("coder", coder_node)
    graph.add_node("reviewer", reviewer_node)

    # Définir le point d'entrée
    graph.set_entry_point("analyst")

    # Définir les connexions linéaires
    graph.add_edge("analyst", "enricher")
    graph.add_edge("enricher", "coder")
    graph.add_edge("coder", "reviewer")

    # Connexion conditionnelle après le Reviewer
    graph.add_conditional_edges(
        "reviewer",
        route_after_reviewer,
        {
            "coder": "coder",   # Retry → retour au Coder
            "end": END,         # Terminé → sortie du graphe
        },
    )

    return graph.compile()


# ── Singleton du Workflow compilé ────────────────────────────────────
_workflow = None


def get_workflow():
    """Retourne le workflow compilé (lazy singleton)."""
    global _workflow
    if _workflow is None:
        _workflow = build_workflow()
        logger.info("langgraph_workflow_compiled")
    return _workflow


# ── Point d'entrée principal ─────────────────────────────────────────

async def process_finding(
    finding: dict,
    scan_id: str,
    project_id: str,
) -> AIAnalysisResult:
    """
    Traite UN finding à travers le pipeline complet.

    C'est LA fonction qu'on appelle depuis le Consumer RabbitMQ.
    Elle orchestre les 4 agents et retourne un AIAnalysisResult
    prêt à être sérialisé et publié dans la queue ai.results.

    Args:
        finding: Dict d'un Finding (SARIF, camelCase ou snake_case)
        scan_id: UUID du scan
        project_id: UUID du projet

    Returns:
        AIAnalysisResult complet avec analyse, enrichissement, patch, et review
    """
    rule_id = finding.get("rule_id", finding.get("ruleId", "unknown"))
    start_time = time.perf_counter()

    logger.info(
        "pipeline_started",
        scan_id=scan_id,
        rule_id=rule_id,
    )

    # ── Construire le state initial ──────────────────────────────
    initial_state: MantisState = {
        "finding": finding,
        "scan_id": scan_id,
        "project_id": project_id,
        "analysis": None,
        "enrichment": None,
        "patch": None,
        "review": None,
        "retry_count": 0,
        "reviewer_feedback": "",
        "current_agent": "analyst",
        "error": None,
        "processing_start_ms": time.time() * 1000,
        "model_used": settings.LLM_MODEL_NAME,
        "messages": [],
    }

    # ── Exécuter le workflow ─────────────────────────────────────
    workflow = get_workflow()

    try:
        final_state = await workflow.ainvoke(initial_state)
    except Exception as e:
        logger.error("pipeline_crashed", scan_id=scan_id, rule_id=rule_id, error=str(e))
        final_state = {**initial_state, "error": str(e)}

    # ── Calculer le temps de traitement ──────────────────────────
    elapsed_ms = int((time.perf_counter() - start_time) * 1000)

    # ── Construire le résultat Pydantic ──────────────────────────
    result = _build_result(final_state, scan_id, project_id, rule_id, elapsed_ms)

    logger.info(
        "pipeline_completed",
        scan_id=scan_id,
        rule_id=rule_id,
        status=result.overall_status.value,
        elapsed_ms=elapsed_ms,
        retries=final_state.get("retry_count", 0),
    )

    # Log de l'audit trail
    for msg in final_state.get("messages", []):
        logger.debug("pipeline_audit", message=msg)

    return result


def _build_result(
    state: dict,
    scan_id: str,
    project_id: str,
    rule_id: str,
    elapsed_ms: int,
) -> AIAnalysisResult:
    """
    Construit un AIAnalysisResult Pydantic à partir du state brut.

    Gère les cas où certains agents ont échoué (résultats None).
    """
    # ── Analysis ─────────────────────────────────────────────────
    analysis_data = state.get("analysis") or {}
    analysis = VulnerabilityAnalysis(
        rule_id=analysis_data.get("rule_id", rule_id),
        severity=analysis_data.get("severity", "MEDIUM"),
        explanation=analysis_data.get("explanation", "Analyse non disponible."),
        impact=analysis_data.get("impact", "Impact non évalué."),
        attack_scenario=analysis_data.get("attack_scenario", ""),
        cwe_id=analysis_data.get("cwe_id"),
        cvss_score=analysis_data.get("cvss_score"),
    )

    # ── Enrichment ───────────────────────────────────────────────
    enrichment_data = state.get("enrichment") or {}
    enrichment = EnrichmentData(
        cve_ids=enrichment_data.get("cve_ids", []),
        ghsa_ids=enrichment_data.get("ghsa_ids", []),
        references=enrichment_data.get("references", []),
        known_exploits=enrichment_data.get("known_exploits", False),
        similar_findings=enrichment_data.get("similar_findings", []),
        enrichment_context=enrichment_data.get("enrichment_context", ""),
    )

    # ── Patch ────────────────────────────────────────────────────
    patch_data = state.get("patch")
    patch = None
    if patch_data and isinstance(patch_data, dict):
        try:
            patch = PatchSuggestion(
                file_path=patch_data.get("file_path", "unknown"),
                original_code=patch_data.get("original_code", ""),
                patched_code=patch_data.get("patched_code", ""),
                explanation=patch_data.get("explanation", "Pas d'explication."),
                confidence=float(patch_data.get("confidence", 0.5)),
            )
        except Exception:
            patch = None

    # ── Review ───────────────────────────────────────────────────
    review_data = state.get("review")
    review = None
    if review_data and isinstance(review_data, dict):
        try:
            review = ReviewResult(
                approved=review_data.get("approved", False),
                feedback=review_data.get("feedback", ""),
                security_check_passed=review_data.get("security_check_passed", True),
                introduces_regression=review_data.get("introduces_regression", False),
            )
        except Exception:
            review = None

    # ── Assembler le résultat final ──────────────────────────────
    return AIAnalysisResult(
        scan_id=scan_id,
        project_id=project_id,
        finding_rule_id=rule_id,
        analysis=analysis,
        enrichment=enrichment,
        patch=patch,
        review=review,
        processing_time_ms=elapsed_ms,
        model_used=state.get("model_used", settings.LLM_MODEL_NAME),
        error=state.get("error"),
    )
