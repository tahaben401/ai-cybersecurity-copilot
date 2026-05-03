"""
MANTIS AI Service — Security Enrichment Wrapper.

Pattern Façade pour orchestrer les différents outils d'enrichissement de sécurité.
Ce module exécute en parallèle les requêtes vers le NVD et GitHub Advisory,
puis fusionne intelligemment et déduplique les résultats pour fournir
un contexte propre et consolidé à l'Enricher Agent.
"""
import asyncio
from typing import Any

from app.core.logger import logger
from app.tools.github_advisory import github_advisory_client
from app.tools.nvd_client import nvd_client


class SecurityEnrichmentWrapper:
    """
    Façade unifiant l'accès aux bases de vulnérabilités externes.
    """

    async def enrich_cwe(self, cwe_id: str, max_results_per_source: int = 3) -> dict[str, Any]:
        """
        Exécute en parallèle NVD et GitHub Advisory pour un CWE donné.
        Fusionne les résultats et élimine les doublons basés sur le CVE ID.

        Args:
            cwe_id: L'identifiant CWE (ex: "CWE-89")
            max_results_per_source: Nombre max de résultats demandés à chaque source

        Returns:
            Un dictionnaire structuré contenant les IDs uniques et le contexte textuel consolidé.
        """
        if not cwe_id:
            return {
                "cve_ids": [],
                "ghsa_ids": [],
                "references": [],
                "context_parts": [],
            }

        logger.info("security_wrapper_started", cwe_id=cwe_id)

        # ── 1. Exécution Parallèle (asyncio.gather) ──────────────────────────
        nvd_task = nvd_client.search_by_cwe(cwe_id, max_results=max_results_per_source)
        gh_task = github_advisory_client.search_by_cwe(cwe_id, max_results=max_results_per_source)

        results = await asyncio.gather(nvd_task, gh_task, return_exceptions=True)

        nvd_results = results[0] if not isinstance(results[0], Exception) else []
        if isinstance(results[0], Exception):
            logger.error("security_wrapper_nvd_failed", error=str(results[0]))

        gh_results = results[1] if not isinstance(results[1], Exception) else []
        if isinstance(results[1], Exception):
            logger.error("security_wrapper_gh_failed", error=str(results[1]))

        # ── 2. Déduplication et Fusion ────────────────────────────────────────
        unique_cves: set[str] = set()
        ghsa_ids: list[str] = []
        references: set[str] = set()
        context_parts: list[str] = []

        # Traitement NVD
        for nvd in nvd_results:
            cve = nvd.get("cve_id")
            if cve and cve not in unique_cves:
                unique_cves.add(cve)
                desc = nvd.get("description", "")
                if desc:
                    context_parts.append(
                        f"[NVD] CVE {cve} (CVSS: {nvd.get('cvss_score', 'N/A')}): {desc[:250]}"
                    )
                for ref in nvd.get("references", [])[:2]:
                    references.add(ref)

        # Traitement GitHub Advisory (évite de remettre un CVE déjà vu)
        for gh in gh_results:
            ghsa = gh.get("ghsa_id")
            cve = gh.get("cve_id")
            
            if ghsa:
                ghsa_ids.append(ghsa)

            if cve and cve in unique_cves:
                continue  # Déjà traité via NVD

            if cve:
                unique_cves.add(cve)
            
            identifier = cve if cve else ghsa
            desc = gh.get("summary", gh.get("description", ""))
            if identifier and desc:
                context_parts.append(
                    f"[GitHub] {identifier} (Sévérité: {gh.get('severity')}): {desc[:250]}"
                )
            for ref in gh.get("references", [])[:2]:
                references.add(ref)

        logger.info(
            "security_wrapper_completed",
            cwe_id=cwe_id,
            unique_cves=len(unique_cves),
            ghsa_count=len(ghsa_ids),
        )

        return {
            "cve_ids": list(unique_cves),
            "ghsa_ids": ghsa_ids,
            "references": list(references)[:5],  # Limite globale des refs
            "context_parts": context_parts,
        }


# Singleton
security_enrichment_wrapper = SecurityEnrichmentWrapper()
