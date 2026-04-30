"""
MANTIS AI Service — State du Graphe LangGraph.

Le State est l'objet qui circule entre tous les agents du pipeline.
C'est le "tableau de bord" partagé que chaque agent peut lire et enrichir.

Flux du State:
    ┌────────────────────────────────────────────────────────────────────┐
    │                        MantisState                                │
    │                                                                   │
    │  [Finding brut]                                                   │
    │       │                                                           │
    │       ▼                                                           │
    │  ┌─────────┐  analysis   ┌──────────┐  enrichment  ┌─────────┐  │
    │  │ Analyst │───────────▶│ Enricher │─────────────▶│  Coder  │  │
    │  └─────────┘             └──────────┘              └────┬────┘  │
    │                                                         │       │
    │                                          patch          │       │
    │                                                         ▼       │
    │                          ┌──────────┐              ┌─────────┐  │
    │                          │  Output  │◀─────────────│Reviewer │  │
    │                          └──────────┘   approved    └────┬────┘  │
    │                                                         │       │
    │                                             rejected    │       │
    │                                          ┌──────────────┘       │
    │                                          ▼ (retry → Coder)      │
    └────────────────────────────────────────────────────────────────────┘

Pourquoi TypedDict et pas Pydantic ?
    LangGraph utilise TypedDict pour le state car il a besoin de
    "reducers" (fonctions de merge) que Pydantic ne supporte pas.
    On utilise Annotated pour définir comment les champs sont mis à jour.
"""
from typing import TypedDict, Annotated
from operator import add


class MantisState(TypedDict, total=False):
    """
    État partagé entre les 4 agents du pipeline.

    Chaque agent lit les champs dont il a besoin et écrit ses résultats.
    Le state est immutable — chaque noeud retourne un NOUVEAU dict partiel
    qui est mergé dans le state existant par LangGraph.

    Attributs:
        === Input (rempli par le Consumer RabbitMQ) ===
        finding: Le Finding SARIF brut (dict sérialisé depuis Finding)
        scan_id: UUID du scan Spring Boot
        project_id: UUID du projet

        === Analyst Agent Output ===
        analysis: Analyse détaillée de la vulnérabilité

        === Enricher Agent Output ===
        enrichment: Données CVE + RAG contextuelles

        === Coder Agent Output ===
        patch: Patch de code proposé

        === Reviewer Agent Output ===
        review: Verdict du Reviewer

        === Contrôle de flux ===
        retry_count: Nombre de boucles Coder→Reviewer effectuées
        reviewer_feedback: Feedback du Reviewer transmis au Coder lors d'un retry
        current_agent: Nom de l'agent en cours d'exécution
        error: Message d'erreur si le pipeline échoue

        === Métadonnées ===
        processing_start_ms: Timestamp de début en ms (pour mesurer la durée)
        model_used: Modèle LLM utilisé
    """

    # ── Input ────────────────────────────────────────────────────────
    finding: dict
    scan_id: str
    project_id: str

    # ── Agent Outputs ────────────────────────────────────────────────
    analysis: dict | None
    enrichment: dict | None
    patch: dict | None
    review: dict | None

    # ── Contrôle de flux ─────────────────────────────────────────────
    retry_count: int
    reviewer_feedback: str
    current_agent: str
    error: str | None

    # ── Métadonnées ──────────────────────────────────────────────────
    processing_start_ms: float
    model_used: str

    # ── Historique des messages (pour le debug/audit) ────────────────
    messages: Annotated[list[str], add]
