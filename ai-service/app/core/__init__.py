"""
MANTIS AI Service — Core Package.

Modules fondamentaux importés par tout le projet:
    - config: Variables d'environnement (Settings singleton)
    - logger: Logging structuré (structlog)
    - exceptions: Exceptions métier personnalisées
"""
from app.core.config import settings
from app.core.logger import logger

__all__ = ["settings", "logger"]
