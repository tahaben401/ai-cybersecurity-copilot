"""
MANTIS AI Service — Helper pour CodeQL.

Fournit des fonctions d'utilité pour interpréter les résultats spécifiques à CodeQL.
"""
from typing import Optional


def parse_codeql_rule(rule_id: str) -> str:
    """
    Tente de déduire la catégorie de vulnérabilité à partir du rule_id CodeQL.
    CodeQL utilise souvent le format: language/category/name (ex: java/sql-injection).
    """
    parts = rule_id.split("/")
    if len(parts) >= 2:
        return f"Catégorie CodeQL: {parts[-2].replace('-', ' ').title()} - {parts[-1].replace('-', ' ').title()}"
    return rule_id


def extract_codeql_severity(raw_severity: str) -> str:
    """
    Mappe la sévérité interne de CodeQL vers le standard MANTIS.
    CodeQL: error, warning, recommendation, note
    """
    mapping = {
        "error": "CRITICAL",
        "warning": "MEDIUM",
        "recommendation": "LOW",
        "note": "INFO"
    }
    return mapping.get(raw_severity.lower(), "MEDIUM")
