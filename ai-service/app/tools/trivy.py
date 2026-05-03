"""
MANTIS AI Service — Helper pour Trivy.

Fournit des fonctions d'utilité pour interpréter les résultats spécifiques à Trivy.
Trivy est souvent utilisé pour les conteneurs et les dépendances (IaC / SBOM).
"""

def parse_trivy_rule(rule_id: str) -> str:
    """
    Formate le rule_id de Trivy. (ex: CVE-2024-1234 ou AVD-AWS-0001)
    """
    if rule_id.startswith("CVE-"):
        return f"Vulnerability {rule_id}"
    elif rule_id.startswith("AVD-"):
        return f"Misconfiguration {rule_id}"
    return rule_id
