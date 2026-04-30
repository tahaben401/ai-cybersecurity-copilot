"""
MANTIS AI Service — LLM Factory.

Factory Pattern pour créer et gérer les instances LLM (Google Gemini 2.5 Flash).

Pourquoi un Factory ?
    1. Abstraction du provider — si on change de LLM demain (OpenAI, Anthropic),
       on modifie UNIQUEMENT ce fichier. Tous les agents restent inchangés.
    2. Configuration centralisée — température, tokens max, callbacks, tous gérés ici.
    3. Instances spécialisées — le Reviewer utilise temp=0 (déterministe),
       le Coder utilise temp=0.2 (légèrement créatif).
    4. Singleton intelligent — on réutilise les instances plutôt que d'en recréer.

Architecture:
    factory.py (ce fichier)
    ├── create_llm()          → Crée une instance LLM avec params customisés
    ├── get_default_llm()     → Retourne le LLM par défaut (singleton lazy)
    ├── get_reviewer_llm()    → LLM spécialisé pour la review (temp=0)
    └── get_creative_llm()    → LLM pour la génération de patch (temp=0.2)

Usage:
    from app.models.factory import get_default_llm, get_reviewer_llm

    llm = get_default_llm()
    response = await llm.ainvoke([SystemMessage(...), HumanMessage(...)])
"""
from functools import lru_cache
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.language_models import BaseChatModel

from app.core.config import settings
from app.core.logger import logger


def create_llm(
    temperature: float | None = None,
    max_tokens: int | None = None,
    model_name: str | None = None,
    top_p: float = 0.95,
    top_k: int = 40,
) -> BaseChatModel:
    """
    Crée une instance LLM Google Gemini configurée.

    Args:
        temperature: Contrôle la créativité (0 = déterministe, 1 = créatif).
                     None → utilise la valeur du .env
        max_tokens: Nombre max de tokens en sortie.
                    None → utilise la valeur du .env
        model_name: Modèle Gemini à utiliser.
                    None → utilise la valeur du .env (gemini-2.5-flash)
        top_p: Nucleus sampling — probabilité cumulative des tokens considérés.
               0.95 est un bon défaut pour du code (assez diversifié mais pas chaotique).
        top_k: Nombre de tokens candidats à considérer à chaque étape.
               40 est le défaut Google, bon pour un équilibre qualité/diversité.

    Returns:
        Instance BaseChatModel prête à être utilisée avec LangChain/LangGraph.

    Exemple:
        llm = create_llm(temperature=0.0)  # Pour des réponses déterministes
        response = await llm.ainvoke(messages)
    """
    model = model_name or settings.LLM_MODEL_NAME
    temp = temperature if temperature is not None else settings.LLM_TEMPERATURE
    tokens = max_tokens or settings.LLM_MAX_TOKENS

    logger.info(
        "llm_instance_created",
        model=model,
        temperature=temp,
        max_tokens=tokens,
        top_p=top_p,
    )

    return ChatGoogleGenerativeAI(
        model=model,
        temperature=temp,
        max_output_tokens=tokens,
        top_p=top_p,
        top_k=top_k,
        google_api_key=settings.GOOGLE_API_KEY,
        convert_system_message_to_human=False,
    )


# ── Instances spécialisées (Lazy Singletons) ────────────────────────
# On utilise @lru_cache pour créer chaque instance UNE SEULE FOIS.
# Avantages:
#   - Pas de reconnexion à chaque appel d'agent
#   - Économie mémoire (pas de duplication)
#   - Les paramètres sont gelés à la première création


@lru_cache(maxsize=1)
def get_default_llm() -> BaseChatModel:
    """
    LLM par défaut — utilisé par l'Analyst Agent et l'Enricher.

    Paramètres:
        - Température 0.1 → Précis et factuel, légère variation
        - Adapté pour l'analyse de vulnérabilités (besoin de rigueur)
    """
    logger.info("creating_default_llm")
    return create_llm(temperature=0.1)


@lru_cache(maxsize=1)
def get_coder_llm() -> BaseChatModel:
    """
    LLM spécialisé pour le Coder Agent.

    Paramètres:
        - Température 0.2 → Légèrement plus créatif que le défaut
        - Le Coder a besoin d'un peu de créativité pour trouver
          des solutions élégantes aux vulnérabilités
        - Mais pas trop — le code doit rester correct et compilable
    """
    logger.info("creating_coder_llm")
    return create_llm(temperature=0.2)


@lru_cache(maxsize=1)
def get_reviewer_llm() -> BaseChatModel:
    """
    LLM spécialisé pour le Reviewer Agent.

    Paramètres:
        - Température 0.0 → Totalement déterministe
        - Le Reviewer DOIT être strict et cohérent
        - Même patch en entrée → même verdict en sortie
        - Pas de place pour la créativité dans la validation
    """
    logger.info("creating_reviewer_llm")
    return create_llm(temperature=0.0)
