"""
MANTIS AI Service — Configuration Centralisée.

Toutes les variables d'environnement sont définies ici.
Pydantic-settings les charge automatiquement depuis le fichier .env.

Architecture:
    .env → Settings (Pydantic) → importé partout via `from app.core.config import settings`

Choix technologiques:
    - LLM: Google Gemini 2.5 Flash (rapide, puissant, coût-efficace)
    - Vector Store: ChromaDB (local, gratuit, pas besoin de cloud)
    - Embeddings: HuggingFace BAAI/bge-base-en-v1.5 (meilleur modèle de retrieval)
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path


class Settings(BaseSettings):
    """
    Configuration centralisée du AI Service.

    Chaque attribut correspond à une variable d'environnement.
    Les valeurs par défaut permettent de lancer l'app sans .env en mode dev.
    """

    # ── LLM — Google Gemini ──────────────────────────────────────────
    GOOGLE_API_KEY: str = Field(
        ...,
        description="Clé API Google AI Studio pour Gemini"
    )
    LLM_MODEL_NAME: str = Field(
        default="gemini-2.5-flash",
        description="Modèle Gemini à utiliser"
    )
    LLM_TEMPERATURE: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description="Température du LLM (0 = déterministe, 2 = créatif)"
    )
    LLM_MAX_TOKENS: int = Field(
        default=8192,
        gt=0,
        description="Nombre maximum de tokens en sortie"
    )

    # ── RabbitMQ ─────────────────────────────────────────────────────
    RABBITMQ_HOST: str = Field(default="localhost")
    RABBITMQ_PORT: int = Field(default=5672, ge=1, le=65535)
    RABBITMQ_USER: str = Field(default="guest")
    RABBITMQ_PASSWORD: str = Field(default="guest")
    RABBITMQ_CONSUME_QUEUE: str = Field(
        default="scan.results",
        description="Queue d'entrée — Taha y publie les rapports SARIF"
    )
    RABBITMQ_PUBLISH_QUEUE: str = Field(
        default="ai.results",
        description="Queue de sortie — On y publie les résultats AI"
    )

    # ── Redis (Semantic Cache) ───────────────────────────────────────
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="URL de connexion Redis"
    )
    CACHE_TTL_SECONDS: int = Field(
        default=86400,
        gt=0,
        description="Durée de vie du cache en secondes (24h par défaut)"
    )

    # ── ChromaDB (Vector Store Local) ────────────────────────────────
    CHROMA_PERSIST_DIR: str = Field(
        default="./data/chromadb",
        description="Répertoire de persistance ChromaDB"
    )
    CHROMA_COLLECTION_NAME: str = Field(
        default="mantis-cve-knowledge",
        description="Nom de la collection ChromaDB"
    )

    # ── Embeddings — HuggingFace ─────────────────────────────────────
    EMBEDDING_MODEL_NAME: str = Field(
        default="BAAI/bge-base-en-v1.5",
        description=(
            "Modèle HuggingFace pour les embeddings. "
            "bge-base-en-v1.5 est le meilleur pour le retrieval (RAG). "
            "768 dimensions, optimisé pour la recherche sémantique."
        )
    )

    # ── NVD API ──────────────────────────────────────────────────────
    NVD_API_KEY: str = Field(
        default="",
        description="Clé API NVD (optionnelle, augmente le rate limit)"
    )
    NVD_BASE_URL: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0"
    )

    # ── Application ──────────────────────────────────────────────────
    APP_ENV: str = Field(
        default="development",
        description="Environnement: development, staging, production"
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Niveau de log: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    MAX_REVIEW_RETRIES: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Nombre max de retries Coder→Reviewer avant abandon"
    )

    @property
    def rabbitmq_url(self) -> str:
        """Construit l'URL AMQP complète pour aio-pika."""
        return (
            f"amqp://{self.RABBITMQ_USER}:{self.RABBITMQ_PASSWORD}"
            f"@{self.RABBITMQ_HOST}:{self.RABBITMQ_PORT}/"
        )

    @property
    def chroma_persist_path(self) -> Path:
        """Retourne le chemin absolu du répertoire ChromaDB."""
        return Path(self.CHROMA_PERSIST_DIR).resolve()

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


# ── Singleton ────────────────────────────────────────────────────────
# Importé partout avec: from app.core.config import settings
# L'instance est créée une seule fois au démarrage.
settings = Settings()
