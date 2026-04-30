"""
MANTIS AI Service — Test End-to-End du Pipeline LangGraph.

Ce test simule un rapport SARIF contenant une SQL Injection
et le fait passer à travers les 4 agents :
    Analyst → Enricher → Coder → Reviewer

C'est le test le plus important du projet : il prouve que
tout le système fonctionne de bout en bout avec Gemini 2.5 Flash.
"""
import sys
import json
import asyncio

sys.path.insert(0, ".")


# Simule un Finding SARIF réel comme Taha l'enverrait
FAKE_FINDING = {
    "ruleId": "java.lang.security.audit.sqli.tainted-sql-from-http-request",
    "toolName": "Semgrep",
    "severity": "HIGH",
    "message": "Untrusted input from HTTP request is used in a SQL query. This could lead to SQL injection.",
    "filePath": "src/main/java/com/mantis/repository/UserRepository.java",
    "startLine": 42,
    "endLine": 47,
    "startColumn": 8,
    "endColumn": 72,
    "cweId": "CWE-89",
    "owaspCategory": "A03:2021-Injection",
    "snippet": """public User findByUsername(String username) {
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(query, new UserRowMapper());
}""",
    "fingerprint": "a1b2c3d4e5f6g7h8",
    "ruleDescription": "SQL injection via string concatenation in JDBC query",
    "suggestedFix": "Use parameterized queries with JdbcTemplate",
}


async def main():
    print("=" * 70)
    print("  MANTIS AI — Test End-to-End Pipeline LangGraph")
    print("  Gemini 2.5 Flash + ChromaDB RAG + BM25 Hybrid Search")
    print("=" * 70)

    # Initialiser le RAG
    from app.rag.vector_store import vector_store
    try:
        vector_store.initialize()
        print(f"\n[RAG] ChromaDB initialise ({vector_store.document_count} documents)")
    except Exception as e:
        print(f"\n[RAG] ChromaDB init warning: {e}")

    # Lancer le pipeline
    from app.graph.workflow import process_finding

    print(f"\n[INPUT] Finding: {FAKE_FINDING['ruleId']}")
    print(f"[INPUT] Fichier: {FAKE_FINDING['filePath']}")
    print(f"[INPUT] CWE: {FAKE_FINDING['cweId']}")
    print(f"[INPUT] Snippet: {FAKE_FINDING['snippet'][:80]}...")
    print("\n" + "-" * 70)
    print("  Lancement du pipeline (4 agents)...")
    print("-" * 70)

    result = await process_finding(
        finding=FAKE_FINDING,
        scan_id="test-scan-001",
        project_id="test-project-001",
    )

    # Afficher les resultats
    print("\n" + "=" * 70)
    print("  RESULTATS")
    print("=" * 70)

    print(f"\n[STATUS] {result.overall_status.value}")
    print(f"[TEMPS]  {result.processing_time_seconds}s")
    print(f"[MODEL]  {result.model_used}")

    print(f"\n--- Analyse (Analyst Agent) ---")
    print(f"  Severite: {result.analysis.severity}")
    print(f"  CWE:      {result.analysis.cwe_id}")
    print(f"  CVSS:     {result.analysis.cvss_score}")
    print(f"  Explication: {result.analysis.explanation[:200]}...")

    print(f"\n--- Enrichissement (Enricher Agent) ---")
    print(f"  CVEs trouves: {result.enrichment.cve_ids[:3]}")
    print(f"  Qualite: {result.enrichment.enrichment_quality}")

    if result.patch:
        print(f"\n--- Patch (Coder Agent) ---")
        print(f"  Fichier: {result.patch.file_path}")
        print(f"  Confiance: {result.patch.confidence} ({result.patch.confidence_label})")
        print(f"  Code corrige:")
        for line in result.patch.patched_code.split("\n")[:10]:
            print(f"    {line}")
    else:
        print(f"\n--- Patch ---")
        print(f"  Aucun patch genere")

    if result.review:
        print(f"\n--- Review (Reviewer Agent) ---")
        print(f"  Approuve: {result.review.approved}")
        print(f"  Securite OK: {result.review.security_check_passed}")
        print(f"  Feedback: {result.review.feedback[:200]}...")

    if result.error:
        print(f"\n[ERREUR] {result.error}")

    # Sauvegarder le JSON complet
    json_output = result.model_dump_json(indent=2)
    with open("test_e2e_result.json", "w", encoding="utf-8") as f:
        f.write(json_output)
    print(f"\n[SAVE] Resultat complet sauvegarde dans test_e2e_result.json ({len(json_output)} chars)")

    print("\n" + "=" * 70)
    print("  TEST E2E TERMINE !")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
