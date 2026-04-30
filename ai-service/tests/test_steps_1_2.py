"""
Test de validation des Étapes 1 & 2 — Fondations + Schémas.

Ce script vérifie que tous les modules s'importent et fonctionnent correctement :
1. Config (pydantic-settings avec .env)
2. Logger (structlog)
3. Exceptions (hiérarchie complète)
4. Schémas SARIF entrants (correspondance avec FindingDTO.java)
5. Schémas AI sortants (résultats du pipeline)
"""
import sys
import json

# S'assurer que le path est correct
sys.path.insert(0, ".")


def test_config():
    """Test 1 : Configuration centralisée"""
    print("\n" + "=" * 60)
    print("TEST 1 — Configuration (config.py)")
    print("=" * 60)

    from app.core.config import settings

    print(f"  ✅ LLM Model:       {settings.LLM_MODEL_NAME}")
    print(f"  ✅ LLM Temp:        {settings.LLM_TEMPERATURE}")
    print(f"  ✅ LLM Max Tokens:  {settings.LLM_MAX_TOKENS}")
    print(f"  ✅ RabbitMQ URL:    {settings.rabbitmq_url}")
    print(f"  ✅ ChromaDB Dir:    {settings.chroma_persist_path}")
    print(f"  ✅ Embedding Model: {settings.EMBEDDING_MODEL_NAME}")
    print(f"  ✅ App Env:         {settings.APP_ENV}")
    print(f"  ✅ Max Retries:     {settings.MAX_REVIEW_RETRIES}")

    assert settings.LLM_MODEL_NAME == "gemini-2.5-flash-preview-04-17"
    assert settings.EMBEDDING_MODEL_NAME == "BAAI/bge-base-en-v1.5"
    print("  ✅ Config PASSED")


def test_logger():
    """Test 2 : Logger structuré"""
    print("\n" + "=" * 60)
    print("TEST 2 — Logger (logger.py)")
    print("=" * 60)

    from app.core.logger import logger

    logger.info("test_log_entry", module="test", status="ok")
    logger.warning("test_warning", detail="ceci est un test")
    print("  ✅ Logger PASSED")


def test_exceptions():
    """Test 3 : Exceptions métier"""
    print("\n" + "=" * 60)
    print("TEST 3 — Exceptions (exceptions.py)")
    print("=" * 60)

    from app.core.exceptions import (
        MantisAIException,
        SarifParsingError,
        LLMInvocationError,
        BrokerConnectionError,
        PatchGenerationError,
        PatchReviewRejected,
        RAGRetrievalError,
        EmbeddingError,
    )

    # Tester chaque exception
    exceptions = [
        SarifParsingError("champ ruleId manquant"),
        LLMInvocationError("gemini-2.5-flash", "quota exceeded"),
        BrokerConnectionError("connection refused"),
        PatchGenerationError("java/sql-injection", "snippet trop court"),
        PatchReviewRejected("le patch n'utilise pas PreparedStatement"),
        RAGRetrievalError("collection non trouvée"),
        EmbeddingError("BAAI/bge-base-en-v1.5", "modèle non téléchargé"),
    ]

    for exc in exceptions:
        assert isinstance(exc, MantisAIException)
        assert exc.code
        assert exc.message
        d = exc.to_dict()
        assert "error_code" in d
        assert "error_message" in d
        print(f"  ✅ {exc.__class__.__name__}: [{exc.code}]")

    print("  ✅ Exceptions PASSED")


def test_sarif_schema():
    """Test 4 : Schéma SARIF entrant (doit matcher FindingDTO.java)"""
    print("\n" + "=" * 60)
    print("TEST 4 — Schéma SARIF (sarif_schema.py)")
    print("=" * 60)

    from app.schemas.sarif_schema import Finding, ScanResultMessage, SeverityLevel

    # Test SeverityLevel enum
    assert SeverityLevel.from_string("CRITICAL") == SeverityLevel.CRITICAL
    assert SeverityLevel.from_string("ERROR") == SeverityLevel.HIGH  # Alias Semgrep
    assert SeverityLevel.from_string("WARNING") == SeverityLevel.MEDIUM  # Alias
    assert SeverityLevel.from_string("NOTE") == SeverityLevel.LOW  # Alias CodeQL
    print("  ✅ SeverityLevel aliases OK")

    # Test Finding — JSON camelCase (comme Taha envoie)
    java_json = {
        "ruleId": "java/sql-injection",
        "toolName": "Semgrep",
        "severity": "HIGH",
        "message": "SQL injection via string concatenation",
        "filePath": "src/main/java/com/app/UserDao.java",
        "startLine": 42,
        "endLine": 45,
        "startColumn": 12,
        "endColumn": 68,
        "cweId": "CWE-89",
        "owaspCategory": "A03:2021",
        "snippet": 'String query = "SELECT * FROM users WHERE id = " + userId;',
        "fingerprint": "a1b2c3d4e5f6",
        "ruleDescription": "SQL Injection via string concatenation",
        "suggestedFix": "Use PreparedStatement with parameterized queries",
    }

    finding = Finding.model_validate(java_json)

    # Vérifier la correspondance avec FindingDTO.java
    assert finding.rule_id == "java/sql-injection"
    assert finding.tool_name == "Semgrep"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.file_path == "src/main/java/com/app/UserDao.java"
    assert finding.start_line == 42
    assert finding.end_line == 45
    assert finding.start_column == 12
    assert finding.end_column == 68
    assert finding.cwe_id == "CWE-89"
    assert finding.owasp_category == "A03:2021"
    assert finding.snippet is not None
    assert finding.fingerprint == "a1b2c3d4e5f6"
    assert finding.rule_description is not None
    assert finding.suggested_fix is not None
    print("  ✅ Finding: 14/14 champs matchent FindingDTO.java")

    # Test computed properties
    assert finding.location_str == "src/main/java/com/app/UserDao.java:42-45"
    assert finding.has_code_context is True
    print("  ✅ Finding computed properties OK")

    # Test ScanResultMessage
    scan_message = {
        "scanId": "550e8400-e29b-41d4-a716-446655440000",
        "projectId": "project-123",
        "branch": "develop",
        "findings": [java_json, java_json],
    }

    scan = ScanResultMessage.model_validate(scan_message)
    assert scan.scan_id == "550e8400-e29b-41d4-a716-446655440000"
    assert scan.findings_count == 2
    assert scan.critical_count == 0
    assert scan.high_count == 2
    assert scan.severity_summary == {"HIGH": 2}
    print(f"  ✅ ScanResultMessage: {scan.findings_count} findings, severity={scan.severity_summary}")

    # Test sérialisation JSON
    json_output = scan.model_dump_json()
    assert len(json_output) > 100
    print(f"  ✅ Sérialisation JSON OK ({len(json_output)} chars)")

    print("  ✅ SARIF Schema PASSED")


def test_patch_schema():
    """Test 5 : Schéma AI sortant"""
    print("\n" + "=" * 60)
    print("TEST 5 — Schéma Patch (patch_schema.py)")
    print("=" * 60)

    from app.schemas.patch_schema import (
        VulnerabilityAnalysis,
        EnrichmentData,
        PatchSuggestion,
        ReviewResult,
        AIAnalysisResult,
        AIBatchResult,
        PatchStatus,
    )

    # VulnerabilityAnalysis
    analysis = VulnerabilityAnalysis(
        rule_id="java/sql-injection",
        severity="CRITICAL",
        explanation="Ce code construit une requête SQL par concaténation de strings, ce qui permet à un attaquant d'injecter du SQL arbitraire.",
        impact="Un attaquant peut extraire, modifier ou supprimer toutes les données de la base de données.",
        attack_scenario="1. L'attaquant saisit ' OR 1=1 -- dans le champ userId",
        cwe_id="CWE-89",
        cvss_score=9.8,
    )
    assert analysis.severity == "CRITICAL"
    print("  ✅ VulnerabilityAnalysis OK")

    # EnrichmentData
    enrichment = EnrichmentData(
        cve_ids=["CVE-2024-12345", "CVE-2024-67890"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"],
        known_exploits=True,
        similar_findings=["Similar SQL injection in Spring Boot JDBC..."],
    )
    assert enrichment.enrichment_quality == "HIGH"
    print(f"  ✅ EnrichmentData OK (quality={enrichment.enrichment_quality})")

    # PatchSuggestion
    patch = PatchSuggestion(
        file_path="src/main/java/com/app/UserDao.java",
        original_code='String query = "SELECT * FROM users WHERE id = " + userId;',
        patched_code='PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
        explanation="Utilisation de PreparedStatement pour empêcher l'injection SQL.",
        confidence=0.92,
    )
    assert patch.is_meaningful_change is True
    assert patch.confidence_label == "HIGH"
    print(f"  ✅ PatchSuggestion OK (confidence={patch.confidence_label}, meaningful={patch.is_meaningful_change})")

    # ReviewResult
    review = ReviewResult(
        approved=True,
        feedback="Bon patch. Le PreparedStatement empêche l'injection SQL.",
        security_check_passed=True,
        introduces_regression=False,
    )
    assert review.status == PatchStatus.APPROVED
    print(f"  ✅ ReviewResult OK (status={review.status.value})")

    # AIAnalysisResult (un finding complet)
    result = AIAnalysisResult(
        scan_id="scan-123",
        project_id="project-456",
        finding_rule_id="java/sql-injection",
        analysis=analysis,
        enrichment=enrichment,
        patch=patch,
        review=review,
        processing_time_ms=3500,
        model_used="gemini-2.5-flash-preview-04-17",
    )
    assert result.overall_status == PatchStatus.APPROVED
    assert result.processing_time_seconds == 3.5
    print(f"  ✅ AIAnalysisResult OK (status={result.overall_status.value}, time={result.processing_time_seconds}s)")

    # AIBatchResult (un scan complet)
    batch = AIBatchResult(
        scan_id="scan-123",
        project_id="project-456",
        results=[result],
        total_findings=5,
        total_processed=1,
        total_patches_generated=1,
        total_patches_approved=1,
    )
    assert batch.success_rate == 0.2
    assert batch.patch_approval_rate == 1.0
    print(f"  ✅ AIBatchResult OK (success={batch.success_rate}, approval={batch.patch_approval_rate})")
    print(f"  ✅ Summary: {batch.summary_str()}")

    # Test sérialisation JSON complète
    json_output = batch.model_dump_json(indent=2)
    parsed = json.loads(json_output)
    assert "results" in parsed
    assert "severity_breakdown" in parsed
    print(f"  ✅ Sérialisation JSON complète OK ({len(json_output)} chars)")

    print("  ✅ Patch Schema PASSED")


if __name__ == "__main__":
    print("🧠 MANTIS AI Service — Tests Étapes 1 & 2")
    print("=" * 60)

    test_config()
    test_logger()
    test_exceptions()
    test_sarif_schema()
    test_patch_schema()

    print("\n" + "=" * 60)
    print("🎉 TOUS LES TESTS PASSENT — Étapes 1 & 2 validées !")
    print("=" * 60)
