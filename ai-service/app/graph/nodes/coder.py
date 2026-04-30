"""
MANTIS AI Service — Node Coder Agent.

Troisième noeud du graphe LangGraph.
Génère un patch de code sécurisé pour corriger la vulnérabilité.
Utilise le contexte RAG+NVD de l'Enricher pour un patch plus intelligent.
"""
import json
from langchain_core.messages import SystemMessage, HumanMessage

from app.graph.state import MantisState
from app.models.factory import get_coder_llm
from app.models.callbacks import MantisLLMCallback
from app.cache.semantic_cache import semantic_cache
from app.core.logger import logger
from app.prompts.coder import (
    CODER_SYSTEM_PROMPT,
    CODER_HUMAN_PROMPT,
    CODER_RETRY_CONTEXT,
)
from app.core.config import settings


async def coder_node(state: MantisState) -> dict:
    """
    Coder Agent — Génération de patch sécurisé.

    Input:  state["finding"], state["analysis"], state["enrichment"]
    Output: state["patch"] (dict de PatchSuggestion)
    """
    finding = state["finding"]
    analysis = state.get("analysis") or {}
    enrichment = state.get("enrichment") or {}
    retry_count = state.get("retry_count", 0)
    reviewer_feedback = state.get("reviewer_feedback", "")
    rule_id = finding.get("rule_id", finding.get("ruleId", "unknown"))

    logger.info("coder_started", rule_id=rule_id, retry=retry_count)

    # ── 1. Cache (seulement si c'est la première tentative) ──────
    if retry_count == 0:
        cached = await semantic_cache.get_patch(
            rule_id=rule_id,
            cwe_id=analysis.get("cwe_id"),
            snippet=finding.get("snippet"),
        )
        if cached:
            logger.info("coder_cache_hit", rule_id=rule_id)
            return {
                "patch": cached,
                "current_agent": "reviewer",
                "messages": [f"[Coder] Cache hit pour {rule_id}"],
            }

    # ── 2. Construire le contexte de retry ───────────────────────
    retry_ctx = ""
    if retry_count > 0 and reviewer_feedback:
        retry_ctx = CODER_RETRY_CONTEXT.format(
            retry_count=retry_count,
            max_retries=settings.MAX_REVIEW_RETRIES,
            reviewer_feedback=reviewer_feedback,
        )

    # ── 3. Construire le prompt ──────────────────────────────────
    human_msg = CODER_HUMAN_PROMPT.format(
        rule_id=rule_id,
        severity=analysis.get("severity", finding.get("severity", "MEDIUM")),
        explanation=analysis.get("explanation", finding.get("message", "N/A")),
        impact=analysis.get("impact", "N/A"),
        cwe_id=analysis.get("cwe_id", finding.get("cwe_id", finding.get("cweId", "N/A"))),
        file_path=finding.get("file_path", finding.get("filePath", "N/A")),
        snippet=finding.get("snippet", "// Code non disponible"),
        enrichment_context=enrichment.get("enrichment_context", "Aucun contexte disponible."),
        retry_context=retry_ctx,
    )

    messages = [
        SystemMessage(content=CODER_SYSTEM_PROMPT),
        HumanMessage(content=human_msg),
    ]

    # ── 4. Appeler Gemini (Coder LLM — temp=0.2) ────────────────
    llm = get_coder_llm()
    callback = MantisLLMCallback(agent_name="coder")

    try:
        response = await llm.ainvoke(messages, config={"callbacks": [callback]})
        raw_text = response.content.strip()

        # Nettoyer le JSON
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[1]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

        patch = json.loads(raw_text)

        # S'assurer que file_path est présent
        if "file_path" not in patch:
            patch["file_path"] = finding.get("file_path", finding.get("filePath", "unknown"))

        # ── 5. Sauvegarder en cache (seulement si première tentative) ─
        if retry_count == 0:
            await semantic_cache.set_patch(
                rule_id=rule_id,
                result=patch,
                cwe_id=analysis.get("cwe_id"),
                snippet=finding.get("snippet"),
            )

        logger.info(
            "coder_completed",
            rule_id=rule_id,
            confidence=patch.get("confidence", 0),
            retry=retry_count,
        )

        return {
            "patch": patch,
            "current_agent": "reviewer",
            "messages": [
                f"[Coder] Patch généré (confidence={patch.get('confidence', '?')}, "
                f"retry={retry_count})"
            ],
        }

    except json.JSONDecodeError as e:
        logger.error("coder_json_parse_failed", rule_id=rule_id, error=str(e))
        return {
            "patch": None,
            "error": f"Coder JSON parse error: {str(e)}",
            "current_agent": "reviewer",
            "messages": [f"[Coder] ⚠️ Erreur parsing JSON: {str(e)[:80]}"],
        }

    except Exception as e:
        logger.error("coder_failed", rule_id=rule_id, error=str(e))
        return {
            "patch": None,
            "error": f"Coder error: {str(e)}",
            "current_agent": "reviewer",
            "messages": [f"[Coder] ❌ Erreur: {str(e)[:100]}"],
        }
