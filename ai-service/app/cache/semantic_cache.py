"""
MANTIS AI Service — Cache Sémantique Redis.

Cache intelligent qui évite de rappeler Gemini pour des vulnérabilités déjà analysées.

Comment ça fonctionne ?
    1. Hash le triplet (rule_id, cwe_id, snippet_prefix) → clé unique
    2. Vérifie si cette clé existe dans Redis
    3. Si OUI (cache hit) → retourne le résultat stocké, pas d'appel LLM
    4. Si NON (cache miss) → appel LLM → stocke le résultat pour la prochaine fois

Pourquoi c'est indispensable ?
    - Un projet type a 50-200 findings après un scan Semgrep
    - Beaucoup de findings sont des VARIANTES du même problème
      (ex: 15 SQL injections dans 15 fichiers différents → même analyse)
    - Sans cache: 200 findings × 4 agents × ~3s = 40 minutes + $$$$
    - Avec cache: 200 findings → ~50 uniques → 10 minutes + $
    - Économie potentielle: 60-80% des appels LLM

Architecture du cache:
    Redis
    ├── mantis:analysis:{hash}    → Résultat de l'Analyst (TTL 24h)
    ├── mantis:enrichment:{hash}  → Résultat de l'Enricher (TTL 12h)
    └── mantis:patch:{hash}       → Résultat du Coder (TTL 6h)
       (Les patches ont un TTL court car le code source change souvent)

Usage:
    from app.cache.semantic_cache import semantic_cache

    # Vérifier le cache avant d'appeler le LLM
    cached = await semantic_cache.get_analysis("java/sql-injection", "CWE-89", snippet)
    if cached:
        return cached  # Pas besoin d'appeler Gemini !

    # Après l'appel LLM, sauvegarder
    await semantic_cache.set_analysis("java/sql-injection", result, "CWE-89", snippet)
"""
import json
import hashlib
from typing import Any

import redis.asyncio as aioredis

from app.core.config import settings
from app.core.logger import logger


class SemanticCache:
    """
    Cache async Redis pour les résultats d'analyse de vulnérabilités.

    Le cache est "sémantique" car il ne compare pas les chaînes exactes
    mais utilise un hash du contenu pertinent. Deux findings avec le même
    rule_id + CWE + snippet similaire auront le même hash → cache hit.
    """

    # Préfixes pour les différents types de résultats
    PREFIX_ANALYSIS = "mantis:analysis"
    PREFIX_ENRICHMENT = "mantis:enrichment"
    PREFIX_PATCH = "mantis:patch"

    # TTL différents selon le type (en secondes)
    TTL_ANALYSIS = 86400       # 24h — les analyses sont stables
    TTL_ENRICHMENT = 43200     # 12h — les CVE changent modérément
    TTL_PATCH = 21600          # 6h  — le code source change souvent

    def __init__(self) -> None:
        self._client: aioredis.Redis | None = None
        self._connected: bool = False

    async def connect(self) -> None:
        """
        Établit la connexion à Redis.

        En cas d'échec, le cache est désactivé silencieusement.
        Le système fonctionne sans cache (juste plus lent et plus cher).
        """
        try:
            self._client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
                retry_on_timeout=True,
            )
            # Test de connexion
            await self._client.ping()
            self._connected = True
            logger.info("redis_cache_connected", url=settings.REDIS_URL)
        except Exception as e:
            self._connected = False
            logger.warning(
                "redis_cache_unavailable",
                error=str(e),
                detail="Le cache est désactivé. Le système fonctionne sans cache.",
            )

    @property
    def is_connected(self) -> bool:
        """Vérifie si Redis est connecté et opérationnel."""
        return self._connected and self._client is not None

    # ── Méthodes de hash ─────────────────────────────────────────────

    @staticmethod
    def _build_key(prefix: str, rule_id: str, cwe_id: str | None, snippet: str | None) -> str:
        """
        Crée une clé de cache déterministe.

        La clé est un hash SHA-256 du contenu pertinent.
        On ne prend que les 200 premiers caractères du snippet car :
        - Les premiers caractères contiennent la logique vulnérable
        - Ça évite les collisions dues aux commentaires ou whitespace
        - C'est plus rapide à hasher
        """
        raw = f"{rule_id}|{cwe_id or 'none'}|{(snippet or '')[:200].strip()}"
        content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"{prefix}:{content_hash}"

    # ── GET / SET pour chaque type ───────────────────────────────────

    async def get_analysis(
        self,
        rule_id: str,
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> dict[str, Any] | None:
        """Cherche un résultat d'analyse en cache."""
        return await self._get(self.PREFIX_ANALYSIS, rule_id, cwe_id, snippet)

    async def set_analysis(
        self,
        rule_id: str,
        result: dict[str, Any],
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> None:
        """Sauvegarde un résultat d'analyse en cache."""
        await self._set(self.PREFIX_ANALYSIS, rule_id, result, cwe_id, snippet, self.TTL_ANALYSIS)

    async def get_enrichment(
        self,
        rule_id: str,
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> dict[str, Any] | None:
        """Cherche un résultat d'enrichissement en cache."""
        return await self._get(self.PREFIX_ENRICHMENT, rule_id, cwe_id, snippet)

    async def set_enrichment(
        self,
        rule_id: str,
        result: dict[str, Any],
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> None:
        """Sauvegarde un résultat d'enrichissement en cache."""
        await self._set(self.PREFIX_ENRICHMENT, rule_id, result, cwe_id, snippet, self.TTL_ENRICHMENT)

    async def get_patch(
        self,
        rule_id: str,
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> dict[str, Any] | None:
        """Cherche un patch en cache."""
        return await self._get(self.PREFIX_PATCH, rule_id, cwe_id, snippet)

    async def set_patch(
        self,
        rule_id: str,
        result: dict[str, Any],
        cwe_id: str | None = None,
        snippet: str | None = None,
    ) -> None:
        """Sauvegarde un patch en cache."""
        await self._set(self.PREFIX_PATCH, rule_id, result, cwe_id, snippet, self.TTL_PATCH)

    # ── Méthodes internes ────────────────────────────────────────────

    async def _get(
        self,
        prefix: str,
        rule_id: str,
        cwe_id: str | None,
        snippet: str | None,
    ) -> dict[str, Any] | None:
        """Méthode interne de lecture du cache."""
        if not self.is_connected:
            return None

        key = self._build_key(prefix, rule_id, cwe_id, snippet)

        try:
            cached = await self._client.get(key)  # type: ignore[union-attr]
            if cached:
                logger.info("cache_hit", prefix=prefix, rule_id=rule_id, key=key[-12:])
                return json.loads(cached)

            logger.debug("cache_miss", prefix=prefix, rule_id=rule_id)
            return None

        except Exception as e:
            logger.warning("cache_get_error", error=str(e), key=key[-12:])
            return None

    async def _set(
        self,
        prefix: str,
        rule_id: str,
        result: dict[str, Any],
        cwe_id: str | None,
        snippet: str | None,
        ttl: int,
    ) -> None:
        """Méthode interne d'écriture dans le cache."""
        if not self.is_connected:
            return

        key = self._build_key(prefix, rule_id, cwe_id, snippet)

        try:
            await self._client.set(  # type: ignore[union-attr]
                key,
                json.dumps(result, ensure_ascii=False),
                ex=ttl,
            )
            logger.info("cache_set", prefix=prefix, rule_id=rule_id, ttl_seconds=ttl)

        except Exception as e:
            logger.warning("cache_set_error", error=str(e), key=key[-12:])

    # ── Utilitaires ──────────────────────────────────────────────────

    async def get_stats(self) -> dict[str, Any]:
        """Retourne des statistiques du cache Redis."""
        if not self.is_connected:
            return {"status": "disconnected"}

        try:
            info = await self._client.info("stats")  # type: ignore[union-attr]
            return {
                "status": "connected",
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
                "hit_rate": round(
                    info.get("keyspace_hits", 0)
                    / max(info.get("keyspace_hits", 0) + info.get("keyspace_misses", 0), 1),
                    2,
                ),
            }
        except Exception:
            return {"status": "error"}

    async def flush_all(self) -> None:
        """Vide tout le cache (utile pour les tests ou un reset)."""
        if self.is_connected:
            await self._client.flushdb()  # type: ignore[union-attr]
            logger.info("cache_flushed")

    async def close(self) -> None:
        """Ferme proprement la connexion Redis."""
        if self._client:
            await self._client.close()
            self._connected = False
            logger.info("redis_cache_disconnected")


# ── Singleton ────────────────────────────────────────────────────────
# Importé partout avec: from app.cache.semantic_cache import semantic_cache
semantic_cache = SemanticCache()
