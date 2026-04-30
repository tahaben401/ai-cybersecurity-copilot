"""
MANTIS AI Service — Callbacks LLM (Observabilité).

Callbacks LangChain pour tracer et mesurer les appels au LLM Gemini.

Pourquoi c'est critique pour un projet de cybersécurité ?
    1. Coût — Chaque appel LLM coûte de l'argent. On doit savoir combien on dépense.
    2. Performance — Si un agent met 30s à répondre, on doit le voir immédiatement.
    3. Debugging — Quand un patch est mauvais, on doit pouvoir retracer l'appel LLM.
    4. Audit — En cybersécurité, la traçabilité est non-négociable.

Usage:
    from app.models.callbacks import MantisLLMCallback, TokenTracker

    # Avec un LLM
    llm = create_llm()
    response = await llm.ainvoke(messages, config={"callbacks": [MantisLLMCallback()]})

    # Tracking global des tokens
    tracker = TokenTracker()
    print(f"Total tokens: {tracker.total_tokens}")
"""
import time
from typing import Any
from langchain_core.callbacks import BaseCallbackHandler
from app.core.logger import logger


class MantisLLMCallback(BaseCallbackHandler):
    """
    Callback principal pour observer les appels LLM.

    Trace pour chaque appel:
        - Quel agent appelle (context)
        - Durée de l'appel en ms
        - Taille du prompt et de la réponse
        - Erreurs éventuelles
    """

    def __init__(self, agent_name: str = "unknown") -> None:
        """
        Args:
            agent_name: Nom de l'agent qui fait l'appel (analyst, coder, reviewer)
                        Permet de filtrer les logs par agent.
        """
        super().__init__()
        self.agent_name = agent_name
        self._start_time: float = 0
        self._prompt_chars: int = 0

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Appelé quand le LLM commence à traiter un prompt."""
        self._start_time = time.perf_counter()
        self._prompt_chars = sum(len(p) for p in prompts)

        logger.info(
            "llm_call_started",
            agent=self.agent_name,
            prompt_chars=self._prompt_chars,
            prompt_count=len(prompts),
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Appelé quand le LLM a fini de répondre."""
        elapsed_ms = int((time.perf_counter() - self._start_time) * 1000)

        # Extraire les infos de token usage si disponibles
        token_info = {}
        if hasattr(response, "llm_output") and response.llm_output:
            usage = response.llm_output.get("token_usage", {})
            if usage:
                token_info = {
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                }

        # Calculer la taille de la réponse
        response_chars = 0
        if hasattr(response, "generations") and response.generations:
            for gen_list in response.generations:
                for gen in gen_list:
                    response_chars += len(gen.text) if hasattr(gen, "text") else 0

        logger.info(
            "llm_call_completed",
            agent=self.agent_name,
            elapsed_ms=elapsed_ms,
            prompt_chars=self._prompt_chars,
            response_chars=response_chars,
            **token_info,
        )

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        """Appelé quand le LLM rencontre une erreur."""
        elapsed_ms = int((time.perf_counter() - self._start_time) * 1000)

        logger.error(
            "llm_call_failed",
            agent=self.agent_name,
            elapsed_ms=elapsed_ms,
            error_type=type(error).__name__,
            error_message=str(error)[:500],
        )


class TokenTracker:
    """
    Compteur global de tokens pour le suivi des coûts.

    Utilisé pour accumuler les tokens sur toute la durée du pipeline.
    Permet de calculer le coût total d'un scan.

    Usage:
        tracker = TokenTracker()
        # ... exécuter le pipeline ...
        print(f"Coût estimé: ${tracker.estimated_cost_usd:.4f}")
    """

    def __init__(self) -> None:
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_calls: int = 0

    @property
    def total_tokens(self) -> int:
        """Nombre total de tokens (prompt + completion)."""
        return self.prompt_tokens + self.completion_tokens

    @property
    def estimated_cost_usd(self) -> float:
        """
        Estimation du coût en USD pour Gemini 2.5 Flash.

        Pricing Gemini 2.5 Flash (approximatif):
            Input:  $0.15 / 1M tokens
            Output: $0.60 / 1M tokens
        """
        input_cost = (self.prompt_tokens / 1_000_000) * 0.15
        output_cost = (self.completion_tokens / 1_000_000) * 0.60
        return input_cost + output_cost

    def record(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Enregistre les tokens d'un appel LLM."""
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.total_calls += 1

    def reset(self) -> None:
        """Remet les compteurs à zéro (début d'un nouveau scan)."""
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_calls = 0

    def summary(self) -> dict[str, Any]:
        """Résumé pour les logs et le monitoring."""
        return {
            "total_calls": self.total_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": round(self.estimated_cost_usd, 6),
        }
