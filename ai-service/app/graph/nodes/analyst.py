"""
MANTIS AI Service — Node Analyst Agent.

Premier noeud du graphe LangGraph.
Transforme un finding brut en une analyse experte de cybersécurité.
"""
import json
import time
from langchain_core.messages import SystemMessage, HumanMessage

from app.graph.state import MantisState
from app.models.factory import get_default_llm
from app.models.callbacks import MantisLLMCallback
from app.cache.semantic_cache import semantic_cache
from app.core.logger import logger
from app.prompts.analyst import ANALYST_SYSTEM_PROMPT, ANALYST_HUMAN_PROMPT


async def analyst_node(state: MantisState) -> dict:
    """
    Analyst Agent — Analyse experte d'une vulnérabilité.

    Input:  state["finding"] (dict du Finding SARIF)
    Output: state["analysis"] (dict de VulnerabilityAnalysis)
    """
    finding = state["finding"]
    rule_id = finding.get("rule_id", finding.get("ruleId", "unknown"))

    logger.info("analyst_started", rule_id=rule_id)

    # ── 1. Vérifier le cache ─────────────────────────────────────
    cached = await semantic_cache.get_analysis(
        rule_id=rule_id,
        cwe_id=finding.get("cwe_id", finding.get("cweId")),
        snippet=finding.get("snippet"),
    )
    if cached:
        logger.info("analyst_cache_hit", rule_id=rule_id)
        return {
            "analysis": cached,
            "current_agent": "enricher",
            "messages": [f"[Analyst] Cache hit pour {rule_id}"],
        }

    # ── 2. Construire le prompt ──────────────────────────────────
    human_msg = ANALYST_HUMAN_PROMPT.format(
        tool_name=finding.get("tool_name", finding.get("toolName", "Unknown")),
        rule_id=rule_id,
        severity=finding.get("severity", "MEDIUM"),
        message=finding.get("message", "N/A"),
        file_path=finding.get("file_path", finding.get("filePath", "N/A")),
        start_line=finding.get("start_line", finding.get("startLine", 0)),
        end_line=finding.get("end_line", finding.get("endLine", 0)),
        cwe_id=finding.get("cwe_id", finding.get("cweId", "N/A")),
        owasp_category=finding.get("owasp_category", finding.get("owaspCategory", "N/A")),
        rule_description=finding.get("rule_description", finding.get("ruleDescription", "N/A")),
        snippet=finding.get("snippet", "// Code non disponible"),
    )

    messages = [
        SystemMessage(content=ANALYST_SYSTEM_PROMPT),
        HumanMessage(content=human_msg),
    ]

    # ── 3. Appeler Gemini ────────────────────────────────────────
    llm = get_default_llm()
    callback = MantisLLMCallback(agent_name="analyst")

    try:
        response = await llm.ainvoke(messages, config={"callbacks": [callback]})
        raw_text = response.content.strip()

        # Nettoyer le JSON (enlever les ```json si Gemini les ajoute)
        if raw_text.startswith("```"):
            raw_text = raw_text.split("\n", 1)[1]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            raw_text = raw_text.strip()

        analysis = json.loads(raw_text)

        # ── 4. Sauvegarder en cache ──────────────────────────────
        await semantic_cache.set_analysis(
            rule_id=rule_id,
            result=analysis,
            cwe_id=finding.get("cwe_id", finding.get("cweId")),
            snippet=finding.get("snippet"),
        )

        logger.info("analyst_completed", rule_id=rule_id, severity=analysis.get("severity"))

        return {
            "analysis": analysis,
            "current_agent": "enricher",
            "messages": [f"[Analyst] Analyse terminée: {rule_id} → {analysis.get('severity')}"],
        }

    except json.JSONDecodeError as e:
        logger.error("analyst_json_parse_failed", rule_id=rule_id, error=str(e))
        # Fallback : créer une analyse minimale
        fallback = {
            "rule_id": rule_id,
            "severity": finding.get("severity", "MEDIUM"),
            "explanation": f"Vulnérabilité détectée par {finding.get('tool_name', 'scanner')}: {finding.get('message', 'N/A')}",
            "impact": "Impact à évaluer manuellement.",
            "attack_scenario": "Scénario non disponible (erreur de parsing LLM).",
            "cwe_id": finding.get("cwe_id", finding.get("cweId")),
            "cvss_score": None,
        }
        return {
            "analysis": fallback,
            "current_agent": "enricher",
            "messages": [f"[Analyst] ⚠️ Fallback: parsing JSON échoué pour {rule_id}"],
        }

    except Exception as e:
        logger.error("analyst_failed", rule_id=rule_id, error=str(e))
        return {
            "analysis": None,
            "error": f"Analyst error: {str(e)}",
            "current_agent": "enricher",
            "messages": [f"[Analyst] ❌ Erreur: {str(e)[:100]}"],
        }
