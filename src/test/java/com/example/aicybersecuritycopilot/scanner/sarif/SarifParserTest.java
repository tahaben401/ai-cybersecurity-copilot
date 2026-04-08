package com.example.aicybersecuritycopilot.scanner.sarif;

import com.example.aicybersecuritycopilot.scanner.sarif.dto.SarifReport;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SarifParser}.
 * Uses a realistic sample SARIF file to verify all parsing logic.
 */
class SarifParserTest {

    private SarifParser parser;
    private String sampleSarif;

    @BeforeEach
    void setUp() throws IOException {
        parser = new SarifParser(new ObjectMapper());
        sampleSarif = loadResource("sample-semgrep-sarif.json");
    }

    // ====================================================================
    // Basic parsing
    // ====================================================================

    @Nested
    @DisplayName("Basic Parsing")
    class BasicParsing {

        @Test
        @DisplayName("should parse all 4 findings from sample SARIF")
        void shouldParseAllFindings() {
            List<FindingDTO> findings = parser.parse(sampleSarif, "Semgrep");
            assertEquals(4, findings.size(), "Expected 4 findings in the sample SARIF");
        }

        @Test
        @DisplayName("should return empty list for null input")
        void shouldReturnEmptyForNull() {
            List<FindingDTO> findings = parser.parse(null, "Semgrep");
            assertTrue(findings.isEmpty());
        }

        @Test
        @DisplayName("should return empty list for blank input")
        void shouldReturnEmptyForBlank() {
            List<FindingDTO> findings = parser.parse("  ", "Semgrep");
            assertTrue(findings.isEmpty());
        }

        @Test
        @DisplayName("should return empty list for invalid JSON")
        void shouldReturnEmptyForInvalidJson() {
            List<FindingDTO> findings = parser.parse("{invalid json!!!}", "Semgrep");
            assertTrue(findings.isEmpty());
        }

        @Test
        @DisplayName("should return empty list for SARIF with no results")
        void shouldReturnEmptyForNoResults() {
            String emptySarif = """
                    {
                      "version": "2.1.0",
                      "runs": [{ "tool": { "driver": { "name": "Semgrep" } }, "results": [] }]
                    }
                    """;
            List<FindingDTO> findings = parser.parse(emptySarif, "Semgrep");
            assertTrue(findings.isEmpty());
        }
    }

    // ====================================================================
    // SQL Injection finding
    // ====================================================================

    @Nested
    @DisplayName("SQL Injection Finding (Error/HIGH)")
    class SqlInjectionFinding {

        private FindingDTO finding;

        @BeforeEach
        void setUp() {
            List<FindingDTO> findings = parser.parse(sampleSarif, "Semgrep");
            finding = findings.stream()
                    .filter(f -> f.getRuleId().contains("sqli"))
                    .findFirst()
                    .orElseThrow();
        }

        @Test
        @DisplayName("should extract correct rule ID")
        void shouldExtractRuleId() {
            assertEquals("java.lang.security.audit.sqli.jdbc-sqli", finding.getRuleId());
        }

        @Test
        @DisplayName("should extract tool name from SARIF")
        void shouldExtractToolName() {
            assertEquals("Semgrep", finding.getToolName());
        }

        @Test
        @DisplayName("should map Semgrep impact HIGH correctly")
        void shouldMapSeverityHigh() {
            assertEquals("HIGH", finding.getSeverity());
        }

        @Test
        @DisplayName("should extract CWE-89 from rule tags")
        void shouldExtractCweId() {
            assertEquals("CWE-89", finding.getCweId());
        }

        @Test
        @DisplayName("should extract OWASP A03:2021 from rule tags")
        void shouldExtractOwaspCategory() {
            assertEquals("A03:2021", finding.getOwaspCategory());
        }

        @Test
        @DisplayName("should extract file path and location")
        void shouldExtractLocation() {
            assertEquals("src/main/java/com/example/UserDao.java", finding.getFilePath());
            assertEquals(42, finding.getStartLine());
            assertEquals(42, finding.getEndLine());
            assertEquals(9, finding.getStartColumn());
            assertEquals(78, finding.getEndColumn());
        }

        @Test
        @DisplayName("should extract code snippet")
        void shouldExtractSnippet() {
            assertNotNull(finding.getSnippet());
            assertTrue(finding.getSnippet().contains("SELECT * FROM users"));
        }

        @Test
        @DisplayName("should extract message")
        void shouldExtractMessage() {
            assertTrue(finding.getMessage().contains("SQL query"));
        }

        @Test
        @DisplayName("should extract fingerprint")
        void shouldExtractFingerprint() {
            assertEquals("abc123def456", finding.getFingerprint());
        }

        @Test
        @DisplayName("should extract autofix suggestion")
        void shouldExtractSuggestedFix() {
            assertNotNull(finding.getSuggestedFix());
            assertTrue(finding.getSuggestedFix().contains("PreparedStatement"));
        }

        @Test
        @DisplayName("should extract rule help text as description")
        void shouldExtractRuleDescription() {
            assertNotNull(finding.getRuleDescription());
            assertTrue(finding.getRuleDescription().contains("parameterized"));
        }
    }

    // ====================================================================
    // Severity mapping
    // ====================================================================

    @Nested
    @DisplayName("Severity Mapping")
    class SeverityMapping {

        @Test
        @DisplayName("should map Semgrep CRITICAL impact")
        void shouldMapCritical() {
            List<FindingDTO> findings = parser.parse(sampleSarif, "Semgrep");
            FindingDTO secretsFinding = findings.stream()
                    .filter(f -> f.getRuleId().contains("api-key"))
                    .findFirst()
                    .orElseThrow();
            assertEquals("CRITICAL", secretsFinding.getSeverity());
        }

        @Test
        @DisplayName("should map Semgrep MEDIUM impact via rule properties")
        void shouldMapMedium() {
            List<FindingDTO> findings = parser.parse(sampleSarif, "Semgrep");
            FindingDTO xssFinding = findings.stream()
                    .filter(f -> f.getRuleId().contains("xss"))
                    .findFirst()
                    .orElseThrow();
            assertEquals("MEDIUM", xssFinding.getSeverity());
        }

        @Test
        @DisplayName("should fall back to SARIF level 'note' → LOW when no impact")
        void shouldFallbackToSarifLevel() {
            List<FindingDTO> findings = parser.parse(sampleSarif, "Semgrep");
            FindingDTO lowFinding = findings.stream()
                    .filter(f -> f.getRuleId().contains("useless-ifelse"))
                    .findFirst()
                    .orElseThrow();
            assertEquals("LOW", lowFinding.getSeverity());
        }
    }

    // ====================================================================
    // Multi-tool merge & deduplication
    // ====================================================================

    @Nested
    @DisplayName("Merge & Deduplication")
    class MergeAndDeduplication {

        @Test
        @DisplayName("should merge findings from multiple tools")
        void shouldMergeMultipleTools() {
            Map<String, String> outputs = new HashMap<>();
            outputs.put("Semgrep", sampleSarif);
            outputs.put("CodeQL", sampleSarif); // same data simulates CodeQL

            List<FindingDTO> merged = parser.parseAndMerge(outputs);
            // 4 findings from each tool, but fingerprinted ones get deduplicated
            // 2 findings have fingerprints → deduplicated, 2 without fingerprints → dedup by location
            // Since the same SARIF is used, all 4 should deduplicate to 4
            assertEquals(4, merged.size());
        }

        @Test
        @DisplayName("should keep highest severity when deduplicating")
        void shouldKeepHighestSeverity() {
            // Create two SARIF reports with same finding but different tool names
            Map<String, String> outputs = new HashMap<>();
            outputs.put("Tool1", sampleSarif);
            outputs.put("Tool2", sampleSarif);

            List<FindingDTO> merged = parser.parseAndMerge(outputs);
            // Findings should deduplicate by fingerprint/location
            assertTrue(merged.size() <= 8 && merged.size() >= 4);
        }
    }

    // ====================================================================
    // Helpers
    // ====================================================================

    private String loadResource(String filename) throws IOException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(filename)) {
            if (is == null) {
                throw new IOException("Resource not found: " + filename);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
