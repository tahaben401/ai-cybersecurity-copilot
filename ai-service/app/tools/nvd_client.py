"""
MANTIS AI Service — Client NVD (National Vulnerability Database).

Client HTTP async pour l'API NVD 2.0 de NIST.
Enrichit les findings avec des données CVE réelles du monde entier.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Rate limits:
    - Sans clé API: 5 requêtes / 30 secondes
    - Avec clé API: 50 requêtes / 30 secondes
    → Recommandé: obtenir une clé gratuite sur https://nvd.nist.gov/developers/request-an-api-key

Ce que le client récupère:
    - CVE IDs associés à un CWE (ex: CWE-89 → CVE-2024-xxxx)
    - Descriptions des vulnérabilités
    - Scores CVSS (sévérité)
    - Références (advisories, patches, PoC)
    - Dates de publication

Usage:
    from app.tools.nvd_client import nvd_client

    results = await nvd_client.search_by_cwe("CWE-89", max_results=5)
    for r in results:
        print(f"{r['cve_id']}: {r['description'][:100]}")
"""
import asyncio
from typing import Any, Optional

import httpx

from app.core.config import settings
from app.core.logger import logger


class NVDClient:
    """
    Client async pour l'API NVD 2.0.

    Gère automatiquement:
    - Rate limiting (respect des limites NVD)
    - Timeouts (30s par requête)
    - Fallback gracieux (retourne [] en cas d'erreur)
    - Parsing des réponses complexes de NVD
    """

    def __init__(self) -> None:
        self._base_url = settings.NVD_BASE_URL
        self._api_key = settings.NVD_API_KEY
        self._last_request_time: float = 0

    async def search_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Cherche des CVEs associés à un CWE donné.

        Args:
            cwe_id: Identifiant CWE (ex: "CWE-89")
            max_results: Nombre max de résultats (1-20)

        Returns:
            Liste de dicts avec cve_id, description, cvss_score, references, published

        Exemple:
            results = await nvd_client.search_by_cwe("CWE-89")
            # → [{"cve_id": "CVE-2024-12345", "description": "SQL injection...", ...}]
        """
        # Normaliser le CWE ID
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        params = {
            "cweId": cwe_id,
            "resultsPerPage": min(max_results, 20),
        }
        return await self._request(params)

    async def search_by_keyword(
        self,
        keyword: str,
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Cherche des CVEs par mot-clé.

        Utile quand on n'a pas de CWE ID mais une description textuelle.

        Args:
            keyword: Termes de recherche (ex: "SQL injection Spring Boot")
            max_results: Nombre max de résultats
        """
        params = {
            "keywordSearch": keyword[:100],  # NVD limite la longueur
            "resultsPerPage": min(max_results, 20),
        }
        return await self._request(params)

    async def get_cve_details(self, cve_id: str) -> Optional[dict[str, Any]]:
        """
        Récupère les détails d'un CVE spécifique.

        Args:
            cve_id: Identifiant CVE (ex: "CVE-2024-12345")
        """
        params = {"cveId": cve_id}
        results = await self._request(params)
        return results[0] if results else None

    async def _request(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Effectue une requête HTTP vers l'API NVD.

        Gère le rate limiting, les timeouts, et parse la réponse.
        """
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        # Rate limiting simple (évite de dépasser les limites NVD)
        await self._rate_limit()

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    self._base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                results = []

                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    parsed = {
                        "cve_id": cve.get("id", ""),
                        "description": self._extract_description(cve),
                        "cvss_score": self._extract_cvss(cve),
                        "severity": self._extract_severity(cve),
                        "references": [
                            ref.get("url", "")
                            for ref in cve.get("references", [])[:5]
                        ],
                        "published": cve.get("published", ""),
                        "last_modified": cve.get("lastModified", ""),
                        "weaknesses": self._extract_weaknesses(cve),
                    }
                    results.append(parsed)

                logger.info(
                    "nvd_search_completed",
                    params_preview=str(params)[:100],
                    results_count=len(results),
                )
                return results

        except httpx.TimeoutException:
            logger.warning("nvd_request_timeout", params=str(params)[:100])
            return []
        except httpx.HTTPStatusError as e:
            logger.warning(
                "nvd_request_http_error",
                status_code=e.response.status_code,
                params=str(params)[:100],
            )
            return []
        except Exception as e:
            logger.error("nvd_request_failed", error=str(e))
            return []

    async def _rate_limit(self) -> None:
        """
        Rate limiting simple pour respecter les limites de NVD.

        Sans clé: 5 req/30s → 1 req/6s
        Avec clé: 50 req/30s → 1 req/0.6s
        """
        import time

        delay = 0.6 if self._api_key else 6.0
        elapsed = time.time() - self._last_request_time

        if elapsed < delay:
            wait = delay - elapsed
            logger.debug("nvd_rate_limit_wait", seconds=round(wait, 2))
            await asyncio.sleep(wait)

        self._last_request_time = time.time()

    # ── Extracteurs de données NVD ───────────────────────────────────

    @staticmethod
    def _extract_description(cve: dict) -> str:
        """Extrait la description en anglais d'un CVE."""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _extract_cvss(cve: dict) -> Optional[float]:
        """Extrait le score CVSS le plus récent disponible."""
        metrics = cve.get("metrics", {})
        # Essayer dans l'ordre de préférence (plus récent d'abord)
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                return metrics[version][0].get("cvssData", {}).get("baseScore")
        return None

    @staticmethod
    def _extract_severity(cve: dict) -> str:
        """Extrait la sévérité textuelle du CVE."""
        metrics = cve.get("metrics", {})
        for version in ["cvssMetricV31", "cvssMetricV30"]:
            if version in metrics and metrics[version]:
                severity = metrics[version][0].get("cvssData", {}).get("baseSeverity")
                if severity:
                    return severity.upper()
        return "UNKNOWN"

    @staticmethod
    def _extract_weaknesses(cve: dict) -> list[str]:
        """Extrait les CWE IDs associés au CVE."""
        weaknesses = cve.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)
        return cwe_ids


# ── Singleton ────────────────────────────────────────────────────────
nvd_client = NVDClient()
