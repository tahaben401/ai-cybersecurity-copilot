"""
MANTIS AI Service — Node Enricher Agent.

Deuxième noeud du graphe LangGraph.
Enrichit l'analyse avec des données CVE réelles (NVD) et
du contexte RAG (ChromaDB + BM25) pour donner au Coder Agent
les meilleures informations possibles.
"""
import json
from app.graph.state import MantisState
from app.tools.nvd_client import nvd_client
from app.rag.vector_store import vector_store
from app.cache.semantic_cache import semantic_cache
from app.core.logger import logger


# ── Détection automatique du langage ─────────────────────────────────

_EXT_TO_LANG = {
    ".java": "java", ".kt": "java", ".scala": "java",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".jsx": "javascript", ".mjs": "javascript",
    ".go": "go",
    ".c": "c", ".cpp": "c", ".cc": "c", ".h": "c", ".hpp": "c",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".swift": "swift",
}


def _detect_language(file_path: str) -> str:
    """
    Détecte le langage de programmation à partir de l'extension du fichier.

    Fallback sur 'java' car c'est le langage principal de MANTIS (Spring Boot),
    mais supporte Python, JS/TS, Go, C/C++, Ruby, PHP, C#, Rust, Swift.
    """
    if not file_path or "." not in file_path:
        return "java"
    ext = "." + file_path.rsplit(".", 1)[-1].lower()
    return _EXT_TO_LANG.get(ext, "java")


async def enricher_node(state: MantisState) -> dict:
    """
    Enricher Agent — Contexte CVE + RAG pour le Coder.

    Input:  state["finding"], state["analysis"]
    Output: state["enrichment"] (dict de EnrichmentData)
    """
    finding = state["finding"]
    analysis = state.get("analysis") or {}
    rule_id = finding.get("rule_id", finding.get("ruleId", "unknown"))
    cwe_id = analysis.get("cwe_id") or finding.get("cwe_id", finding.get("cweId"))
    file_path = finding.get("file_path", finding.get("filePath", ""))
    detected_lang = _detect_language(file_path)

    logger.info("enricher_started", rule_id=rule_id, cwe_id=cwe_id, language=detected_lang)

    # ── 1. Vérifier le cache ─────────────────────────────────────
    cached = await semantic_cache.get_enrichment(
        rule_id=rule_id,
        cwe_id=cwe_id,
        snippet=finding.get("snippet"),
    )
    if cached:
        logger.info("enricher_cache_hit", rule_id=rule_id)
        return {
            "enrichment": cached,
            "current_agent": "coder",
            "messages": [f"[Enricher] Cache hit pour {rule_id}"],
        }

    enrichment = {
        "cve_ids": [],
        "references": [],
        "known_exploits": False,
        "similar_findings": [],
        "enrichment_context": "",
        "detected_language": detected_lang,
    }

    context_parts = []

    # ── 2. Recherche NVD (CVEs réels) ────────────────────────────
    try:
        if cwe_id:
            nvd_results = await nvd_client.search_by_cwe(cwe_id, max_results=3)

            for cve in nvd_results:
                if cve.get("cve_id"):
                    enrichment["cve_ids"].append(cve["cve_id"])

                refs = cve.get("references", [])
                enrichment["references"].extend(refs[:2])

                desc = cve.get("description", "")
                if desc:
                    context_parts.append(
                        f"CVE {cve['cve_id']} (CVSS: {cve.get('cvss_score', 'N/A')}): "
                        f"{desc[:300]}"
                    )

            logger.info("enricher_nvd_done", cve_count=len(enrichment["cve_ids"]))
    except Exception as e:
        logger.warning("enricher_nvd_failed", error=str(e))

    # ── 3. Recherche RAG (ChromaDB Hybrid Search) ────────────────
    try:
        if vector_store.is_initialized:
            # 3a. Recherche par CWE
            if cwe_id:
                cwe_results = await vector_store.search_by_cwe(cwe_id, k=3)
                for doc in cwe_results:
                    enrichment["similar_findings"].append(doc["content"][:200])
                    context_parts.append(doc["content"])

            # 3b. Recherche de fix patterns (avec le BON langage)
            vuln_type = analysis.get("explanation", finding.get("message", ""))
            if vuln_type:
                fix_results = await vector_store.search_fix_patterns(
                    vulnerability_type=vuln_type[:100],
                    language=detected_lang,
                    k=2,
                )
                for doc in fix_results:
                    context_parts.append(f"Fix Pattern ({detected_lang}):\n{doc['content']}")

            # 3c. Recherche OWASP Cheatsheets (bonnes pratiques)
            if vuln_type:
                owasp_results = await vector_store.hybrid_search(
                    query=f"{vuln_type[:80]} security best practices remediation",
                    k=2,
                    filter_metadata={"type": "owasp_cheatsheet"},
                )
                for doc in owasp_results:
                    context_parts.append(
                        f"OWASP Best Practice:\n{doc['content']}"
                    )

            logger.info(
                "enricher_rag_done",
                similar_count=len(enrichment["similar_findings"]),
                language=detected_lang,
            )
    except Exception as e:
        logger.warning("enricher_rag_failed", error=str(e))

    # ── 4. Assembler le contexte d'enrichissement ────────────────
    if context_parts:
        enrichment["enrichment_context"] = "\n\n---\n\n".join(context_parts)
    else:
        enrichment["enrichment_context"] = (
            "Aucun enrichissement trouvé dans NVD ou RAG. "
            "Le Coder devra se baser sur ses connaissances générales."
        )

    # ── 5. Sauvegarder en cache ──────────────────────────────────
    await semantic_cache.set_enrichment(
        rule_id=rule_id,
        result=enrichment,
        cwe_id=cwe_id,
        snippet=finding.get("snippet"),
    )

    quality = "HIGH" if enrichment["cve_ids"] and enrichment["similar_findings"] \
        else "MEDIUM" if enrichment["cve_ids"] or enrichment["similar_findings"] \
        else "LOW"

    logger.info(
        "enricher_completed",
        rule_id=rule_id,
        cve_count=len(enrichment["cve_ids"]),
        rag_count=len(enrichment["similar_findings"]),
        quality=quality,
        language=detected_lang,
    )

    return {
        "enrichment": enrichment,
        "current_agent": "coder",
        "messages": [
            f"[Enricher] {len(enrichment['cve_ids'])} CVEs + "
            f"{len(enrichment['similar_findings'])} RAG docs "
            f"(quality={quality}, lang={detected_lang})"
        ],
    }
