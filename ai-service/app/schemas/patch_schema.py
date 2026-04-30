"""
MANTIS AI Service — Schémas de Sortie (Résultats AI).

Ce module définit les schémas Pydantic pour les résultats produits par le pipeline
multi-agents et envoyés vers la queue RabbitMQ ai.results pour Taha.

Flux des données:
    Analyst Agent → VulnerabilityAnalysis
    Enricher Agent → EnrichmentData
    Coder Agent → PatchSuggestion
    Reviewer Agent → ReviewResult
    ──────────────────────────────────
    Tout combiné → AIAnalysisResult (un finding)
    Liste de résultats → AIBatchResult (un scan complet)

Le AIBatchResult est sérialisé en JSON et publié dans ai.results.
Taha le désérialise côté Java pour sauvegarder en DB et notifier l'utilisateur.
"""
from pydantic import BaseModel, Field, field_validator, computed_field
from typing import Optional
from datetime import datetime, timezone
from enum import Enum


class PatchStatus(str, Enum):
    """Statut du patch dans le pipeline."""
    PENDING = "PENDING"         # En cours de génération
    GENERATED = "GENERATED"     # Patch généré, pas encore reviewé
    APPROVED = "APPROVED"       # Approuvé par le Reviewer
    REJECTED = "REJECTED"       # Rejeté par le Reviewer (après tous les retries)
    FAILED = "FAILED"           # Erreur lors de la génération


class VulnerabilityAnalysis(BaseModel):
    """
    Analyse détaillée d'une vulnérabilité produite par l'Analyst Agent.

    L'Analyst lit les données brutes du scanner SARIF et produit une
    analyse compréhensible par un développeur : explication en langage
    clair, impact réel, et scénario d'attaque réaliste.

    Exemple:
        {
            "rule_id": "java/sql-injection",
            "severity": "CRITICAL",
            "explanation": "Ce code construit une requête SQL par concaténation...",
            "impact": "Un attaquant peut extraire toute la base de données...",
            "attack_scenario": "1. L'attaquant injecte ' OR 1=1 -- ...",
            "cwe_id": "CWE-89",
            "cvss_score": 9.8
        }
    """
    rule_id: str = Field(
        ...,
        description="ID de la règle originale du scanner",
    )
    severity: str = Field(
        ...,
        description="Sévérité réévaluée par l'AI (peut différer du scanner)",
    )
    explanation: str = Field(
        ...,
        min_length=10,
        description="Explication détaillée et compréhensible de la vulnérabilité",
    )
    impact: str = Field(
        ...,
        min_length=10,
        description="Impact potentiel concret sur l'application et ses données",
    )
    attack_scenario: str = Field(
        default="",
        description="Scénario d'attaque réaliste, étape par étape",
    )
    cwe_id: Optional[str] = Field(
        default=None,
        description="CWE ID confirmé ou corrigé par l'AI",
    )
    cvss_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Score CVSS estimé par l'AI (0.0 - 10.0)",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """S'assure que la sévérité est un niveau valide."""
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        upper = v.upper().strip() if isinstance(v, str) else v
        return upper if upper in valid else "MEDIUM"


class EnrichmentData(BaseModel):
    """
    Données d'enrichissement produites par l'Enricher Agent.

    L'Enricher combine deux sources :
    1. NVD API (National Vulnerability Database) → CVEs réels associés
    2. ChromaDB (RAG) → Vulnérabilités similaires et patterns de fix connus

    Ces données donnent du contexte au Coder Agent pour générer
    un patch plus informé et de meilleure qualité.
    """
    cve_ids: list[str] = Field(
        default_factory=list,
        description="IDs des CVEs associés trouvés dans NVD (ex: CVE-2024-12345)",
    )
    references: list[str] = Field(
        default_factory=list,
        description="URLs de référence (advisories, documentation, PoC)",
    )
    known_exploits: bool = Field(
        default=False,
        description="Indique si des exploits publics existent pour cette vuln",
    )
    similar_findings: list[str] = Field(
        default_factory=list,
        description="Descriptions de vulnérabilités similaires trouvées via RAG",
    )
    enrichment_context: str = Field(
        default="",
        description=(
            "Texte résumé du contexte d'enrichissement, "
            "assemblé pour être passé au Coder Agent dans son prompt"
        ),
    )

    @computed_field
    @property
    def enrichment_quality(self) -> str:
        """
        Évalue la qualité de l'enrichissement obtenu.

        HIGH: CVEs trouvés + contexte RAG
        MEDIUM: CVEs OU contexte RAG
        LOW: Aucun enrichissement trouvé
        """
        has_cves = len(self.cve_ids) > 0
        has_rag = len(self.similar_findings) > 0

        if has_cves and has_rag:
            return "HIGH"
        elif has_cves or has_rag:
            return "MEDIUM"
        return "LOW"


class PatchSuggestion(BaseModel):
    """
    Un patch de code généré par le Coder Agent.

    Le patch contient le code original (vulnérable) et le code corrigé,
    avec une explication détaillée de pourquoi le fix fonctionne.

    Le format avant/après permet à Taha de :
    1. Afficher un diff visuel dans le frontend
    2. Appliquer le patch automatiquement (si approuvé)
    3. Créer une Pull Request avec le fix
    """
    file_path: str = Field(
        ...,
        description="Chemin du fichier à modifier",
    )
    original_code: str = Field(
        ...,
        description="Code vulnérable original (avant le patch)",
    )
    patched_code: str = Field(
        ...,
        description="Code corrigé (après le patch)",
    )
    explanation: str = Field(
        ...,
        min_length=10,
        description=(
            "Explication détaillée du patch : "
            "pourquoi ce changement corrige la vulnérabilité, "
            "quelles pratiques de sécurité sont appliquées"
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Niveau de confiance du Coder Agent (0.0 - 1.0). "
            "< 0.5 = patch incertain, > 0.8 = haute confiance"
        ),
    )

    @computed_field
    @property
    def is_meaningful_change(self) -> bool:
        """Vérifie que le patch apporte un vrai changement (pas un no-op)."""
        return (
            self.original_code.strip() != self.patched_code.strip()
            and len(self.patched_code.strip()) > 0
        )

    @computed_field
    @property
    def confidence_label(self) -> str:
        """Label humain pour le niveau de confiance."""
        if self.confidence >= 0.8:
            return "HIGH"
        elif self.confidence >= 0.5:
            return "MEDIUM"
        return "LOW"


class ReviewResult(BaseModel):
    """
    Résultat de la validation par le Reviewer Agent.

    Le Reviewer est le dernier garde-fou avant que le patch soit envoyé
    à Taha. Il vérifie que :
    1. Le patch corrige bien la vulnérabilité
    2. Le patch n'introduit PAS de nouvelles vulnérabilités
    3. Le patch ne casse PAS la logique métier existante
    4. Le patch suit les bonnes pratiques de sécurité
    """
    approved: bool = Field(
        ...,
        description="Le patch est-il approuvé pour déploiement ?",
    )
    feedback: str = Field(
        default="",
        description=(
            "Commentaires détaillés du Reviewer. "
            "Si rejeté, contient les raisons et suggestions d'amélioration."
        ),
    )
    security_check_passed: bool = Field(
        default=True,
        description="Le patch ne crée-t-il pas de nouvelles failles de sécurité ?",
    )
    introduces_regression: bool = Field(
        default=False,
        description="Le patch risque-t-il de casser des fonctionnalités existantes ?",
    )

    @computed_field
    @property
    def status(self) -> PatchStatus:
        """Détermine le statut du patch basé sur la review."""
        if self.approved and self.security_check_passed:
            return PatchStatus.APPROVED
        return PatchStatus.REJECTED


class AIAnalysisResult(BaseModel):
    """
    Résultat complet de l'analyse AI pour UN SEUL finding.

    Combine les résultats des 4 agents du pipeline :
    Analyst → Enricher → Coder → Reviewer

    C'est l'unité atomique de résultat. Un AIBatchResult contient
    une liste de AIAnalysisResult (un par finding du scan).
    """
    scan_id: str = Field(
        ...,
        description="UUID du scan original (lien avec Spring Boot)",
    )
    project_id: str = Field(
        ...,
        description="UUID du projet scanné",
    )
    finding_rule_id: str = Field(
        ...,
        description="Rule ID du finding analysé (lien avec le Finding original)",
    )

    # Résultats de chaque agent
    analysis: VulnerabilityAnalysis = Field(
        ...,
        description="Analyse détaillée de la vulnérabilité (Analyst Agent)",
    )
    enrichment: EnrichmentData = Field(
        default_factory=EnrichmentData,
        description="Données d'enrichissement NVD + RAG (Enricher Agent)",
    )
    patch: Optional[PatchSuggestion] = Field(
        default=None,
        description="Patch de code proposé (Coder Agent) — None si génération échouée",
    )
    review: Optional[ReviewResult] = Field(
        default=None,
        description="Résultat de la review (Reviewer Agent) — None si pas de patch",
    )

    # Métadonnées
    processing_time_ms: int = Field(
        default=0,
        ge=0,
        description="Temps de traitement total en millisecondes",
    )
    processed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp ISO 8601 du traitement",
    )
    model_used: str = Field(
        default="gemini-2.5-flash",
        description="Modèle LLM utilisé pour l'analyse",
    )
    error: Optional[str] = Field(
        default=None,
        description="Message d'erreur si le traitement a partiellement échoué",
    )

    @computed_field
    @property
    def overall_status(self) -> PatchStatus:
        """
        Statut global du résultat.

        APPROVED: Patch généré et approuvé par le Reviewer
        REJECTED: Patch généré mais rejeté
        GENERATED: Patch généré mais pas encore reviewé
        FAILED: Aucun patch généré ou erreur
        """
        if self.error:
            return PatchStatus.FAILED
        if self.review and self.review.approved:
            return PatchStatus.APPROVED
        if self.review and not self.review.approved:
            return PatchStatus.REJECTED
        if self.patch:
            return PatchStatus.GENERATED
        return PatchStatus.FAILED

    @computed_field
    @property
    def processing_time_seconds(self) -> float:
        """Temps de traitement en secondes (plus lisible)."""
        return round(self.processing_time_ms / 1000.0, 2)


class AIBatchResult(BaseModel):
    """
    Lot complet de résultats AI pour un scan entier.

    C'est LE message envoyé vers la queue ai.results pour Taha.
    Contient tous les résultats d'analyse pour chaque finding du scan.

    Structure JSON envoyée:
        {
            "scan_id": "uuid",
            "project_id": "uuid",
            "results": [ ... AIAnalysisResult ... ],
            "total_findings": 10,
            "total_processed": 8,
            "total_patches_generated": 6,
            "total_patches_approved": 4,
            "completed_at": "2024-01-15T10:30:00Z"
        }
    """
    scan_id: str = Field(
        ...,
        description="UUID du scan original",
    )
    project_id: str = Field(
        ...,
        description="UUID du projet scanné",
    )
    results: list[AIAnalysisResult] = Field(
        default_factory=list,
        description="Résultats individuels pour chaque finding",
    )
    total_findings: int = Field(
        default=0,
        ge=0,
        description="Nombre total de findings dans le scan original",
    )
    total_processed: int = Field(
        default=0,
        ge=0,
        description="Nombre de findings effectivement traités par l'AI",
    )
    total_patches_generated: int = Field(
        default=0,
        ge=0,
        description="Nombre de patches générés (avant review)",
    )
    total_patches_approved: int = Field(
        default=0,
        ge=0,
        description="Nombre de patches approuvés par le Reviewer",
    )
    completed_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="Timestamp ISO 8601 de fin de traitement du batch",
    )

    @computed_field
    @property
    def success_rate(self) -> float:
        """Taux de traitement réussi (0.0 - 1.0)."""
        if self.total_findings == 0:
            return 0.0
        return round(self.total_processed / self.total_findings, 2)

    @computed_field
    @property
    def patch_approval_rate(self) -> float:
        """Taux d'approbation des patches (0.0 - 1.0)."""
        if self.total_patches_generated == 0:
            return 0.0
        return round(self.total_patches_approved / self.total_patches_generated, 2)

    @computed_field
    @property
    def severity_breakdown(self) -> dict[str, int]:
        """Répartition des findings par sévérité dans les résultats."""
        breakdown: dict[str, int] = {}
        for result in self.results:
            severity = result.analysis.severity
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

    def summary_str(self) -> str:
        """Retourne un résumé lisible du batch pour les logs."""
        return (
            f"Scan {self.scan_id}: "
            f"{self.total_processed}/{self.total_findings} traités, "
            f"{self.total_patches_approved}/{self.total_patches_generated} patches approuvés"
        )
