"""
MANTIS AI Service — Helper pour Semgrep.

Fournit des fonctions d'utilité pour interpréter les résultats spécifiques à Semgrep.
"""

def parse_semgrep_rule(rule_id: str) -> str:
    """
    Extrait un nom lisible du rule_id de Semgrep.
    Exemple: java.lang.security.audit.sqli.tainted-sql-from-http-request -> Tainted SQL From Http Request
    """
    if "." in rule_id:
        parts = rule_id.split(".")
        return parts[-1].replace("-", " ").title()
    return rule_id


def format_semgrep_message(message: str) -> str:
    """
    Nettoie le message d'erreur de Semgrep pour le prompt du LLM.
    """
    # Remove excessive whitespace
    return " ".join(message.split())
