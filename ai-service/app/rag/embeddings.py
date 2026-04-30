"""
MANTIS AI Service — Embeddings HuggingFace.

Module qui gère le modèle d'embeddings pour le RAG.

Modèle choisi: BAAI/bge-base-en-v1.5
    - 768 dimensions
    - Optimisé spécifiquement pour le RETRIEVAL (pas juste la similarité)
    - Top 1 sur le MTEB Retrieval Benchmark au moment du choix
    - Gratuit, tourne en local (pas d'API, pas de coût)
    - Support du "instruction prefix" : on peut dire au modèle
      "Represent this document for retrieval" pour de meilleurs résultats

Pourquoi bge-base et pas bge-large ?
    - bge-base: 110M params, 768 dims → rapide, ~95% de la qualité de large
    - bge-large: 335M params, 1024 dims → meilleur mais 3x plus lent
    - Pour MANTIS, la vitesse compte (on analyse potentiellement 200 findings)

Pourquoi HuggingFace et pas OpenAI Embeddings ?
    1. Gratuit (pas de coût par embedding)
    2. Tourne en local (pas de latence réseau)
    3. Données restent privées (pas envoyées au cloud)
    4. Pas de rate limiting
"""
from functools import lru_cache
from langchain_huggingface import HuggingFaceEmbeddings
from app.core.config import settings
from app.core.logger import logger


@lru_cache(maxsize=1)
def get_embeddings() -> HuggingFaceEmbeddings:
    """
    Retourne le modèle d'embeddings configuré (singleton lazy).

    Le modèle est téléchargé automatiquement au premier appel
    (~420 MB pour bge-base-en-v1.5) et mis en cache par HuggingFace.

    Le prefix "Represent this sentence: " est recommandé par BAAI
    pour les requêtes de recherche (pas pour les documents).

    Returns:
        Instance HuggingFaceEmbeddings prête à être utilisée avec ChromaDB.
    """
    model_name = settings.EMBEDDING_MODEL_NAME

    logger.info(
        "loading_embedding_model",
        model=model_name,
        detail="Premier chargement peut prendre 30-60s (téléchargement du modèle)",
    )

    embeddings = HuggingFaceEmbeddings(
        model_name=model_name,
        model_kwargs={
            "device": "cpu",  # CPU suffit pour bge-base (pas besoin de GPU)
        },
        encode_kwargs={
            "normalize_embeddings": True,  # Normalisation L2 → meilleure similarité cosine
            "batch_size": 32,              # Batch processing pour la vitesse
        },
    )

    logger.info("embedding_model_loaded", model=model_name, dimensions=768)
    return embeddings
