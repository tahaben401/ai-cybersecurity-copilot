"""
MANTIS AI Service — Exceptions Métier.

Hiérarchie d'exceptions personnalisées pour le domaine cybersécurité.
Chaque exception porte un code unique pour faciliter le debugging
dans un système distribué (Spring Boot ↔ RabbitMQ ↔ AI Service).

Hiérarchie:
    MantisAIException (base)
    ├── SarifParsingError      — SARIF reçu mal formé
    ├── LLMInvocationError     — Appel LLM (Gemini) échoué
    ├── BrokerConnectionError  — Connexion RabbitMQ échouée
    ├── PatchGenerationError   — Génération de patch échouée
    ├── PatchReviewRejected    — Patch rejeté par le Reviewer (retry possible)
    ├── RAGRetrievalError      — Recherche ChromaDB échouée
    └── EmbeddingError         — Génération d'embeddings HuggingFace échouée

Usage:
    from app.core.exceptions import SarifParsingError
    raise SarifParsingError("Champ 'ruleId' manquant dans le finding #3")
"""


class MantisAIException(Exception):
    """
    Exception de base pour tout le AI Service.

    Toutes les exceptions métier héritent de celle-ci, permettant
    un catch générique dans le consumer RabbitMQ.

    Attributes:
        code: Code unique pour identifier le type d'erreur dans les logs
        message: Description humaine de l'erreur
    """

    def __init__(self, message: str, code: str = "AI_GENERIC") -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")

    def to_dict(self) -> dict:
        """Sérialise l'exception pour l'inclure dans un message RabbitMQ d'erreur."""
        return {
            "error_code": self.code,
            "error_message": self.message,
        }


class SarifParsingError(MantisAIException):
    """
    Le rapport SARIF reçu depuis RabbitMQ est mal formé ou incompatible.

    Causes possibles:
        - JSON invalide
        - Champs obligatoires manquants (ruleId, toolName)
        - Format SARIF non supporté
        - Incohérence avec le FindingDTO.java de Taha
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            message=f"Erreur parsing SARIF: {detail}",
            code="SARIF_PARSE_ERROR",
        )


class LLMInvocationError(MantisAIException):
    """
    L'appel au LLM (Gemini 2.5 Flash) a échoué.

    Causes possibles:
        - Clé API invalide ou expirée
        - Quota dépassé
        - Timeout réseau
        - Réponse malformée (pas du JSON valide)
        - Content safety filter déclenché
    """

    def __init__(self, model: str, detail: str) -> None:
        self.model = model
        super().__init__(
            message=f"LLM '{model}' erreur: {detail}",
            code="LLM_INVOCATION_ERROR",
        )


class BrokerConnectionError(MantisAIException):
    """
    Impossible de se connecter à RabbitMQ ou erreur de publication.

    Causes possibles:
        - RabbitMQ non démarré (docker compose up rabbitmq)
        - Mauvais credentials
        - Queue inexistante
        - Connexion perdue en cours de route
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            message=f"RabbitMQ: {detail}",
            code="BROKER_CONNECTION_ERROR",
        )


class PatchGenerationError(MantisAIException):
    """
    La génération du patch de code a échoué.

    Causes possibles:
        - Le Coder Agent n'a pas pu comprendre le code vulnérable
        - Le snippet de code est trop court ou absent
        - Le LLM a retourné un patch vide ou invalide
    """

    def __init__(self, vuln_id: str, detail: str) -> None:
        self.vuln_id = vuln_id
        super().__init__(
            message=f"Patch pour '{vuln_id}': {detail}",
            code="PATCH_GENERATION_ERROR",
        )


class PatchReviewRejected(MantisAIException):
    """
    Le Reviewer Agent a rejeté le patch.

    Ce n'est PAS une erreur fatale — le pipeline va renvoyer au Coder Agent
    avec le feedback du Reviewer (max MAX_REVIEW_RETRIES tentatives).

    Attributes:
        reason: Raison du rejet fournie par le Reviewer
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(
            message=f"Patch rejeté: {reason}",
            code="PATCH_REVIEW_REJECTED",
        )


class RAGRetrievalError(MantisAIException):
    """
    Erreur lors de la recherche dans ChromaDB (vector store).

    Causes possibles:
        - ChromaDB non initialisé
        - Collection inexistante
        - Erreur d'embedding (modèle HuggingFace non téléchargé)
        - Données corrompues dans la base vectorielle
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            message=f"RAG retrieval (ChromaDB): {detail}",
            code="RAG_RETRIEVAL_ERROR",
        )


class EmbeddingError(MantisAIException):
    """
    Erreur lors de la génération d'embeddings avec HuggingFace.

    Causes possibles:
        - Modèle non trouvé ou non téléchargé
        - Texte d'entrée trop long
        - Mémoire insuffisante (GPU/CPU)
    """

    def __init__(self, model: str, detail: str) -> None:
        self.model = model
        super().__init__(
            message=f"Embedding '{model}': {detail}",
            code="EMBEDDING_ERROR",
        )
