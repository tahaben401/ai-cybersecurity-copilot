"""
MANTIS AI Service — Client GitHub Advisory Database.

Client HTTP async pour l'API REST de GitHub Security Advisories.
Permet d'enrichir les données avec des vulnérabilités spécifiques à l'écosystème open source
et de récupérer les GHSA (GitHub Security Advisories) liés à un CWE ou CVE.

API: https://api.github.com/advisories
"""
import asyncio
import time
from typing import Any, Optional

import httpx

from app.core.config import settings
from app.core.logger import logger


class GitHubAdvisoryClient:
    """
    Client async robuste pour l'API GitHub Security Advisories.
    Gère le rate limiting (basé sur le token GitHub), timeouts, et parsing.
    """

    def __init__(self) -> None:
        self._base_url = f"{settings.GITHUB_API_BASE_URL.rstrip('/')}/advisories"
        self._token = settings.GITHUB_API_TOKEN
        self._api_version = settings.GITHUB_API_VERSION
        self._timeout = settings.GITHUB_API_TIMEOUT
        self._last_request_time: float = 0

    async def search_by_cwe(
        self,
        cwe_id: str,
        max_results: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Cherche des GHSA associés à un CWE donné.

        Args:
            cwe_id: Identifiant CWE (ex: "CWE-89"). Si format "89", il sera normalisé.
            max_results: Nombre de résultats à retourner.
        """
        if not cwe_id.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        params = {
            "cwe_id": cwe_id,
            "per_page": min(max_results, 20),
            "sort": "updated",
            "direction": "desc",
        }
        return await self._request(params)

    async def search_by_cve(self, cve_id: str) -> Optional[dict[str, Any]]:
        """
        Cherche un GHSA spécifique via son identifiant CVE.
        """
        params = {"cve_id": cve_id}
        results = await self._request(params)
        return results[0] if results else None

    async def _request(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self._api_version,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        await self._rate_limit()

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    self._base_url,
                    params=params,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                results = []
                for adv in data:
                    parsed = {
                        "ghsa_id": adv.get("ghsa_id", ""),
                        "cve_id": adv.get("cve_id", ""),
                        "summary": adv.get("summary", ""),
                        "description": adv.get("description", ""),
                        "severity": adv.get("severity", "unknown").upper(),
                        "cvss_score": adv.get("cvss", {}).get("score"),
                        "references": [
                            ref.get("url", "")
                            for ref in adv.get("references", [])[:3]
                        ],
                        "published": adv.get("published_at", ""),
                        "withdrawn": adv.get("withdrawn_at"),
                    }
                    results.append(parsed)

                logger.info(
                    "github_advisory_search_completed",
                    params_preview=str(params)[:100],
                    results_count=len(results),
                )
                return results

        except httpx.TimeoutException:
            logger.warning("github_advisory_request_timeout", params=str(params)[:100])
            return []
        except httpx.HTTPStatusError as e:
            logger.warning(
                "github_advisory_request_http_error",
                status_code=e.response.status_code,
                params=str(params)[:100],
            )
            return []
        except Exception as e:
            logger.error("github_advisory_request_failed", error=str(e))
            return []

    async def _rate_limit(self) -> None:
        """
        Rate limiting simplifié pour GitHub API (REST).
        Authentifié: 5000 req/heure (~1.38 req/s).
        Non authentifié: 60 req/heure (1 req/min).
        """
        delay = 1.0 if self._token else 60.0
        elapsed = time.time() - self._last_request_time

        if elapsed < delay:
            wait = delay - elapsed
            logger.debug("github_advisory_rate_limit_wait", seconds=round(wait, 2))
            await asyncio.sleep(wait)

        self._last_request_time = time.time()


# Singleton
github_advisory_client = GitHubAdvisoryClient()
