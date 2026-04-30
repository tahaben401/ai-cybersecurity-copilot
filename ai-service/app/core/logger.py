"""
MANTIS AI Service — Logger Structuré.

Utilise structlog pour produire des logs structurés (JSON en prod, coloré en dev).
Les logs structurés sont essentiels pour le debugging d'un système multi-agents
car chaque entrée porte un contexte riche (scan_id, rule_id, agent, etc.).

Usage:
    from app.core.logger import logger

    logger.info("analyst_started", rule_id="java/sql-injection", scan_id="abc-123")
    logger.error("llm_call_failed", model="gemini-2.5-flash", error="timeout")

Pourquoi structlog et pas logging standard ?
    1. Logs structurés (key=value) → faciles à parser par des outils (ELK, Loki)
    2. Context binding → on peut attacher un scan_id à tous les logs d'un pipeline
    3. Processeurs chaînés → timestamps, niveaux, formatage automatiques
"""
import logging
import structlog


def setup_logging(log_level: str = "INFO", app_env: str = "development") -> None:
    """
    Configure structlog avec le bon renderer selon l'environnement.

    Args:
        log_level: Niveau minimum de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        app_env: Environnement applicatif (development → console colorée, autre → JSON)
    """
    # Choisir le renderer selon l'environnement
    if app_env == "development":
        renderer = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    # Configurer les processeurs structlog
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configurer aussi le logging standard (pour les libs tierces)
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Réduire le bruit des libs tierces
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
    logging.getLogger("aio_pika").setLevel(logging.WARNING)


def get_logger(name: str = "mantis-ai") -> structlog.stdlib.BoundLogger:
    """
    Retourne un logger structuré nommé.

    Args:
        name: Nom du logger (apparaît dans chaque entrée de log)

    Returns:
        Logger structuré prêt à l'emploi
    """
    return structlog.get_logger(name)


# ── Initialisation au premier import ─────────────────────────────────
# On importe les settings ici de manière lazy pour éviter les imports circulaires
# car config.py n'importe PAS logger.py (mais logger.py importe config.py)
def _initialize() -> None:
    """Initialise le logging avec les settings de l'application."""
    try:
        from app.core.config import settings
        setup_logging(
            log_level=settings.LOG_LEVEL,
            app_env=settings.APP_ENV,
        )
    except Exception:
        # Fallback si settings pas encore disponible (ex: tests unitaires)
        setup_logging(log_level="DEBUG", app_env="development")


_initialize()

# ── Logger principal (singleton) ─────────────────────────────────────
# Importé partout avec: from app.core.logger import logger
logger = get_logger("mantis-ai")
