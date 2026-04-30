"""
MANTIS AI Service — Schéma SARIF Entrant.

Ce module définit les schémas Pydantic pour les données SARIF entrantes.
Il DOIT correspondre EXACTEMENT au FindingDTO.java côté Spring Boot (Taha).

Flux des données:
    Spring Boot → serialize FindingDTO → JSON → RabbitMQ (scan.results)
    → Consumer Python → deserialize → ScanResultMessage (ce fichier)

Mapping FindingDTO.java → Finding (Pydantic):
    ┌─────────────────────────────────────────────────────────────┐
    │ Java (camelCase)    │ Python (snake_case)  │ Type           │
    │─────────────────────│──────────────────────│────────────────│
    │ ruleId              │ rule_id              │ str (required) │
    │ toolName            │ tool_name            │ str (required) │
    │ severity            │ severity             │ SeverityLevel  │
    │ message             │ message              │ str            │
    │ filePath            │ file_path            │ str            │
    │ startLine           │ start_line           │ int            │
    │ endLine             │ end_line             │ int            │
    │ startColumn         │ start_column         │ int            │
    │ endColumn           │ end_column           │ int            │
    │ cweId               │ cwe_id               │ str | None     │
    │ owaspCategory       │ owasp_category       │ str | None     │
    │ snippet             │ snippet              │ str | None     │
    │ fingerprint         │ fingerprint          │ str | None     │
    │ ruleDescription     │ rule_description     │ str | None     │
    │ suggestedFix        │ suggested_fix        │ str | None     │
    └─────────────────────────────────────────────────────────────┘

IMPORTANT:
    - populate_by_name=True permet d'accepter BOTH camelCase et snake_case
    - Taha envoie en camelCase (Java convention), Python utilise snake_case
    - Les 14 champs correspondent EXACTEMENT au FindingDTO.java
    - Le champ 'suggested_fix' existe dans le DTO Java mais n'est pas dans
      le plan original — on l'ajoute pour compatibilité complète
"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
from enum import Enum


class SeverityLevel(str, Enum):
    """
    Niveaux de sévérité des vulnérabilités.

    Correspondance CVSS:
        CRITICAL: 9.0 - 10.0
        HIGH:     7.0 - 8.9
        MEDIUM:   4.0 - 6.9
        LOW:      0.1 - 3.9
        INFO:     Informatif, pas de score
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_string(cls, value: str) -> "SeverityLevel":
        """Parse une sévérité depuis une string, avec fallback intelligent."""
        normalized = value.upper().strip()

        # Mapping des alias courants des scanners
        aliases = {
            "ERROR": cls.HIGH,
            "WARNING": cls.MEDIUM,
            "NOTE": cls.LOW,
            "NONE": cls.INFO,
            "INFORMATIONAL": cls.INFO,
        }

        try:
            return cls(normalized)
        except ValueError:
            return aliases.get(normalized, cls.MEDIUM)


class Finding(BaseModel):
    """
    Un seul résultat de scanning de vulnérabilité.

    Correspond EXACTEMENT au FindingDTO.java de Taha (14 champs).
    Chaque Finding représente une vulnérabilité détectée dans le code source.

    Exemple d'un finding réel (Semgrep):
        {
            "ruleId": "java.lang.security.audit.sqli.tainted-sql-from-http-request",
            "toolName": "Semgrep",
            "severity": "HIGH",
            "message": "Untrusted input used in SQL query",
            "filePath": "src/main/java/com/app/UserDao.java",
            "startLine": 42,
            "endLine": 45,
            "startColumn": 12,
            "endColumn": 68,
            "cweId": "CWE-89",
            "owaspCategory": "A03:2021",
            "snippet": "String query = \"SELECT * FROM users WHERE id = \" + userId;",
            "fingerprint": "a1b2c3d4e5f6",
            "ruleDescription": "SQL Injection via string concatenation",
            "suggestedFix": "Use PreparedStatement with parameterized queries"
        }
    """

    # ── Champs obligatoires ──────────────────────────────────────────
    rule_id: str = Field(
        ...,
        alias="ruleId",
        min_length=1,
        description="ID unique de la règle SARIF (ex: java/sql-injection)",
    )
    tool_name: str = Field(
        ...,
        alias="toolName",
        min_length=1,
        description="Scanner source: Semgrep, CodeQL, ou Trivy",
    )
    severity: SeverityLevel = Field(
        ...,
        description="Niveau de sévérité: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    )

    # ── Champs avec valeurs par défaut ───────────────────────────────
    message: str = Field(
        default="",
        description="Description textuelle de la vulnérabilité détectée",
    )
    file_path: str = Field(
        default="",
        alias="filePath",
        description="Chemin du fichier source contenant la vulnérabilité",
    )
    start_line: int = Field(
        default=0,
        alias="startLine",
        ge=0,
        description="Ligne de début de la vulnérabilité dans le fichier",
    )
    end_line: int = Field(
        default=0,
        alias="endLine",
        ge=0,
        description="Ligne de fin de la vulnérabilité dans le fichier",
    )
    start_column: int = Field(
        default=0,
        alias="startColumn",
        ge=0,
        description="Colonne de début",
    )
    end_column: int = Field(
        default=0,
        alias="endColumn",
        ge=0,
        description="Colonne de fin",
    )

    # ── Champs optionnels (enrichissement) ───────────────────────────
    cwe_id: Optional[str] = Field(
        default=None,
        alias="cweId",
        description="Identifiant CWE (ex: CWE-89 pour SQL injection)",
    )
    owasp_category: Optional[str] = Field(
        default=None,
        alias="owaspCategory",
        description="Catégorie OWASP Top 10 (ex: A03:2021)",
    )
    snippet: Optional[str] = Field(
        default=None,
        description="Extrait de code source vulnérable",
    )
    fingerprint: Optional[str] = Field(
        default=None,
        description="Empreinte unique du finding pour la déduplication",
    )
    rule_description: Optional[str] = Field(
        default=None,
        alias="ruleDescription",
        description="Description détaillée de la règle de sécurité",
    )
    suggested_fix: Optional[str] = Field(
        default=None,
        alias="suggestedFix",
        description="Suggestion de fix du scanner (si disponible)",
    )

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        """
        Normalise la sévérité pour gérer les alias des différents scanners.

        Semgrep utilise ERROR/WARNING/INFO
        CodeQL utilise error/warning/note
        SARIF standard utilise CRITICAL/HIGH/MEDIUM/LOW/INFO
        """
        if isinstance(v, str):
            # Convertir via notre enum intelligent
            return SeverityLevel.from_string(v).value
        return v

    @property
    def location_str(self) -> str:
        """Retourne une description lisible de la localisation."""
        if self.file_path:
            return f"{self.file_path}:{self.start_line}-{self.end_line}"
        return "unknown"

    @property
    def has_code_context(self) -> bool:
        """Vérifie si on a assez de contexte pour générer un patch."""
        return bool(self.snippet and self.file_path and self.start_line > 0)

    model_config = {
        "populate_by_name": True,  # Accepte camelCase ET snake_case
        "str_strip_whitespace": True,
    }


class ScanResultMessage(BaseModel):
    """
    Message complet reçu depuis la queue RabbitMQ scan.results.

    C'est l'enveloppe qui contient tous les findings d'un scan.
    Taha envoie un ScanResultMessage après chaque exécution de scanner.

    Structure JSON attendue:
        {
            "scanId": "uuid-du-scan",
            "projectId": "uuid-du-projet",
            "branch": "main",
            "findings": [
                { ... Finding 1 ... },
                { ... Finding 2 ... }
            ],
            "rawSarif": "... SARIF brut complet (optionnel) ..."
        }
    """
    scan_id: str = Field(
        ...,
        alias="scanId",
        min_length=1,
        description="UUID unique du scan côté Spring Boot",
    )
    project_id: str = Field(
        ...,
        alias="projectId",
        min_length=1,
        description="UUID du projet scanné",
    )
    branch: str = Field(
        default="main",
        description="Branche Git scannée",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Liste des vulnérabilités détectées",
    )
    raw_sarif: Optional[str] = Field(
        default=None,
        alias="rawSarif",
        description="Rapport SARIF brut complet (pour archivage/debug)",
    )

    @model_validator(mode="after")
    def validate_findings_consistency(self) -> "ScanResultMessage":
        """
        Valide la cohérence globale du message.

        - Un scan_id valide
        - Si des findings existent, vérifie qu'ils ont des données exploitables
        """
        if self.findings:
            # Compter les findings avec assez de contexte pour l'analyse
            actionable = sum(1 for f in self.findings if f.has_code_context)
            if actionable == 0 and len(self.findings) > 0:
                # Warning silencieux — on traite quand même mais avec moins de précision
                pass
        return self

    @property
    def findings_count(self) -> int:
        """Nombre total de findings dans ce scan."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Nombre de findings CRITICAL."""
        return sum(
            1 for f in self.findings
            if f.severity == SeverityLevel.CRITICAL
        )

    @property
    def high_count(self) -> int:
        """Nombre de findings HIGH."""
        return sum(
            1 for f in self.findings
            if f.severity == SeverityLevel.HIGH
        )

    @property
    def severity_summary(self) -> dict[str, int]:
        """Résumé des findings par sévérité."""
        summary: dict[str, int] = {}
        for finding in self.findings:
            level = finding.severity.value
            summary[level] = summary.get(level, 0) + 1
        return summary

    model_config = {
        "populate_by_name": True,
        "str_strip_whitespace": True,
    }
