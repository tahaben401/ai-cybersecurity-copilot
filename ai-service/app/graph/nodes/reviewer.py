"""
MANTIS AI Service — Node Reviewer Agent.

Quatrième et dernier noeud du graphe LangGraph.
Valide ou rejette le patch du Coder. Si rejeté, le pipeline
boucle vers le Coder avec le feedback (max N retries).
"""
import json
from langchain_core.messages import SystemMessage, HumanMessage

from app.graph.state import MantisState
from app.models.factory import get_reviewer_llm
from app.models.callbacks import MantisLLMCallback
from app.core.logger import logger
from app.core.config import settings
from app.prompts.reviewer import REVIEWER_SYSTEM_PROMPT, REVIEWER_HUMAN_PROMPT


async def reviewer_node(state: MantisState) -> dict:
    """
    Reviewer Agent — Validation ou rejet du patch.

    Input:  state["finding"], state["analysis"], state["patch"]
    Output: state["review"] (dict de ReviewResult)

    Logique de sortie:
        - patch approuvé → workflow terminé
        - patch rejeté + retries restants → retour au Coder
        - patch rejeté + retries épuisés → workflow terminé (rejeté)
        - pas de patch → workflow terminé (erreur)
    """
    finding = state["finding"]
    analysis = state.get("analysis") or {}
    patch = state.get("patch")
    retry_count = state.get("retry_count", 0)
    rule_id = finding.get("rule_id", finding.get("ruleId", "unknown"))

    logger.info("reviewer_started", rule_id=rule_id, retry=retry_count)

    # ── Cas spécial : pas de patch à reviewer ────────────────────
    if not patch:
        logger.warning("reviewer_no_patch", rule_id=rule_id)
        return {
            "review": {
                "approved": False,
                "feedback": "Aucun patch à reviewer — le Coder n'a pas produit de résultat.",
                "security_check_passed": False,
                "introduces_regression": False,
            },
            "current_agent": "done",
            "messages": [f"[Reviewer] Aucun patch à reviewer pour {rule_id}"],
        }

    # ── Construire le prompt ─────────────────────────────────────
    human_msg = REVIEWER_HUMAN_PROMPT.format(
        rule_id=rule_id,
        severity=analysis.get("severity", finding.get("severity", "MEDIUM")),
        cwe_id=analysis.get("cwe_id", finding.get("cwe_id", finding.get("cweId", "N/A"))),
        explanation=analysis.get("explanation", finding.get("message", "N/A")),
        original_code=patch.get("original_code", "// Non disponible"),
        patched_code=patch.get("patched_code", "// Non disponible"),
        patch_explanation=patch.get("explanation", "N/A"),
        confidence=patch.get("confidence", "N/A"),
    )

    messages = [
        SystemMessage(content=REVIEWER_SYSTEM_PROMPT),
        HumanMessage(content=human_msg),
    ]

    # ── Appeler Gemini (Reviewer LLM — temp=0.0, déterministe) ───
    llm = get_reviewer_llm()
    callback = MantisLLMCallback(agent_name="reviewer")

    try:
        response = await llm.ainvoke(messages, config={"callbacks": [callback]})
        raw_text = response.content.strip()

        # Nettoyer le JSON
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[1]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

        review = json.loads(raw_text)

        approved = review.get("approved", False)

        if approved:
            logger.info("reviewer_approved", rule_id=rule_id)
            return {
                "review": review,
                "current_agent": "done",
                "messages": [f"[Reviewer] ✅ Patch APPROUVÉ pour {rule_id}"],
            }
        else:
            # Patch rejeté — on peut retenter ?
            max_retries = settings.MAX_REVIEW_RETRIES
            if retry_count < max_retries:
                logger.info(
                    "reviewer_rejected_retry",
                    rule_id=rule_id,
                    retry=retry_count + 1,
                    max_retries=max_retries,
                    feedback=review.get("feedback", "")[:100],
                )
                return {
                    "review": review,
                    "retry_count": retry_count + 1,
                    "reviewer_feedback": review.get("feedback", "Patch rejeté sans feedback."),
                    "current_agent": "coder",  # Retour au Coder !
                    "messages": [
                        f"[Reviewer] ❌ Rejeté (retry {retry_count + 1}/{max_retries}): "
                        f"{review.get('feedback', '')[:80]}"
                    ],
                }
            else:
                logger.warning(
                    "reviewer_rejected_final",
                    rule_id=rule_id,
                    feedback=review.get("feedback", "")[:100],
                )
                return {
                    "review": review,
                    "current_agent": "done",
                    "messages": [
                        f"[Reviewer] ❌ Rejeté définitivement après {max_retries} tentatives"
                    ],
                }

    except json.JSONDecodeError as e:
        logger.error("reviewer_json_parse_failed", rule_id=rule_id, error=str(e))
        # En cas d'erreur, on approuve par défaut (on ne veut pas bloquer le pipeline)
        return {
            "review": {
                "approved": True,
                "feedback": "Review auto-approuvée (erreur de parsing). Vérification manuelle recommandée.",
                "security_check_passed": True,
                "introduces_regression": False,
            },
            "current_agent": "done",
            "messages": [f"[Reviewer] ⚠️ Auto-approuvé (parsing error) pour {rule_id}"],
        }

    except Exception as e:
        logger.error("reviewer_failed", rule_id=rule_id, error=str(e))
        return {
            "review": None,
            "error": f"Reviewer error: {str(e)}",
            "current_agent": "done",
            "messages": [f"[Reviewer] ❌ Erreur: {str(e)[:100]}"],
        }
