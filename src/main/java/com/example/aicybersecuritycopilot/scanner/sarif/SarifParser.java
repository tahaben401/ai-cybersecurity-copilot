package com.example.aicybersecuritycopilot.scanner.sarif;

import com.example.aicybersecuritycopilot.scanner.sarif.dto.SarifReport;
import com.example.aicybersecuritycopilot.scanner.sarif.dto.SarifReport.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SarifParser {

    private static final Pattern CWE_PATTERN = Pattern.compile("CWE-(\\d+)");
    private static final Pattern OWASP_PATTERN = Pattern.compile("(A\\d{2}:\\d{4})");

    private final ObjectMapper objectMapper;

    public List<FindingDTO> parse(String sarifJson, String toolName) {
        if (sarifJson == null || sarifJson.isBlank()) {
            return Collections.emptyList();
        }
        try {
            SarifReport report = objectMapper.readValue(sarifJson, SarifReport.class);
            return extractFindings(report, toolName);
        } catch (Exception e) {
            log.error("[SarifParser] Failed to parse SARIF: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    public List<FindingDTO> parseAndMerge(Map<String, String> sarifOutputs) {
        List<FindingDTO> allFindings = new ArrayList<>();
        for (Map.Entry<String, String> entry : sarifOutputs.entrySet()) {
            allFindings.addAll(parse(entry.getValue(), entry.getKey()));
        }
        return deduplicateFindings(allFindings);
    }

    private List<FindingDTO> extractFindings(SarifReport report, String fallbackToolName) {
        if (report.getRuns() == null) return Collections.emptyList();

        List<FindingDTO> findings = new ArrayList<>();
        for (SarifRun run : report.getRuns()) {
            String toolName = extractToolName(run, fallbackToolName);
            Map<String, SarifRule> rulesIndex = indexRules(run);

            if (run.getResults() == null) continue;
            for (SarifResult result : run.getResults()) {
                FindingDTO finding = mapResultToFinding(result, toolName, rulesIndex);
                if (finding != null) findings.add(finding);
            }
        }
        return findings;
    }

    private FindingDTO mapResultToFinding(SarifResult result, String toolName, Map<String, SarifRule> rulesIndex) {
        try {
            String filePath = "";
            int startLine = 0, endLine = 0, startColumn = 0, endColumn = 0;
            String snippet = null;

            if (result.getLocations() != null && !result.getLocations().isEmpty()) {
                SarifPhysicalLocation physical = result.getLocations().get(0).getPhysicalLocation();
                if (physical != null) {
                    if (physical.getArtifactLocation() != null) filePath = physical.getArtifactLocation().getUri();
                    if (physical.getRegion() != null) {
                        SarifRegion region = physical.getRegion();
                        startLine = region.getStartLine();
                        endLine = region.getEndLine() > 0 ? region.getEndLine() : startLine;
                        startColumn = region.getStartColumn();
                        endColumn = region.getEndColumn();
                        if (region.getSnippet() != null) snippet = region.getSnippet().getText();
                    }
                }
            }

            SarifRule rule = rulesIndex.get(result.getRuleId());
            return FindingDTO.builder()
                    .ruleId(result.getRuleId())
                    .toolName(toolName)
                    .severity(mapSeverity(result.getLevel(), rule))
                    .message(result.getMessage() != null ? result.getMessage().getText() : "")
                    .filePath(filePath)
                    .startLine(startLine)
                    .endLine(endLine)
                    .startColumn(startColumn)
                    .endColumn(endColumn)
                    .cweId(extractCweId(rule))
                    .owaspCategory(extractOwaspCategory(rule))
                    .snippet(snippet)
                    .fingerprint(result.getFingerprint())
                    .ruleDescription(extractRuleDescription(rule))
                    .suggestedFix(extractSuggestedFix(result))
                    .build();

        } catch (Exception e) {
            return null; // Skip malformed findings quietly
        }
    }

    private String mapSeverity(String sarifLevel, SarifRule rule) {
        if (rule != null && rule.getImpact() != null) {
            String normalized = rule.getImpact().toUpperCase().trim();
            if (isValidSeverity(normalized)) return normalized;
        }
        if (sarifLevel == null) return "INFO";
        return switch (sarifLevel.toLowerCase()) {
            case "error"   -> "HIGH";
            case "warning" -> "MEDIUM";
            case "note"    -> "LOW";
            default        -> "INFO";
        };
    }

    private boolean isValidSeverity(String severity) {
        return severity.equals("CRITICAL") || severity.equals("HIGH")
                || severity.equals("MEDIUM") || severity.equals("LOW") || severity.equals("INFO");
    }

    private String extractToolName(SarifRun run, String fallback) {
        if (run.getTool() != null && run.getTool().getDriver() != null) {
            String name = run.getTool().getDriver().getName();
            if (name != null && !name.isBlank()) return name;
        }
        return fallback;
    }

    private Map<String, SarifRule> indexRules(SarifRun run) {
        if (run.getTool() == null || run.getTool().getDriver() == null || run.getTool().getDriver().getRules() == null) {
            return Collections.emptyMap();
        }
        return run.getTool().getDriver().getRules().stream()
                .filter(r -> r.getId() != null)
                .collect(Collectors.toMap(SarifRule::getId, r -> r, (a, b) -> a));
    }

    private String extractCweId(SarifRule rule) {
        if (rule == null) return null;
        for (String tag : rule.getTags()) {
            Matcher m = CWE_PATTERN.matcher(tag);
            if (m.find()) return "CWE-" + m.group(1);
        }
        return null;
    }

    private String extractOwaspCategory(SarifRule rule) {
        if (rule == null) return null;
        for (String tag : rule.getTags()) {
            Matcher m = OWASP_PATTERN.matcher(tag);
            if (m.find()) return m.group(1);
        }
        return null;
    }

    private String extractRuleDescription(SarifRule rule) {
        if (rule == null) return null;
        if (rule.getHelp() != null && rule.getHelp().getText() != null) return rule.getHelp().getText();
        if (rule.getFullDescription() != null && rule.getFullDescription().getText() != null) return rule.getFullDescription().getText();
        if (rule.getShortDescription() != null && rule.getShortDescription().getText() != null) return rule.getShortDescription().getText();
        return null;
    }

    private String extractSuggestedFix(SarifResult result) {
        if (result.getFixes() == null || result.getFixes().isEmpty()) return null;
        SarifFix fix = result.getFixes().get(0);
        if (fix.getArtifactChanges() != null && !fix.getArtifactChanges().isEmpty()) {
            SarifArtifactChange change = fix.getArtifactChanges().get(0);
            if (change.getReplacements() != null && !change.getReplacements().isEmpty()) {
                SarifReplacement replacement = change.getReplacements().get(0);
                if (replacement.getInsertedContent() != null) return replacement.getInsertedContent().getText();
            }
        }
        return null;
    }

    private List<FindingDTO> deduplicateFindings(List<FindingDTO> findings) {
        Map<String, FindingDTO> uniqueFindings = new LinkedHashMap<>();
        for (FindingDTO finding : findings) {
            String key = buildDeduplicationKey(finding);
            FindingDTO existing = uniqueFindings.get(key);
            if (existing == null || severityRank(finding.getSeverity()) > severityRank(existing.getSeverity())) {
                uniqueFindings.put(key, finding);
            }
        }
        return new ArrayList<>(uniqueFindings.values());
    }

    private String buildDeduplicationKey(FindingDTO finding) {
        if (finding.getFingerprint() != null && !finding.getFingerprint().isBlank()) return finding.getFingerprint();
        return finding.getFilePath() + ":" + finding.getStartLine() + ":" + finding.getRuleId();
    }

    private int severityRank(String severity) {
        if (severity == null) return 0;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 5;
            case "HIGH"     -> 4;
            case "MEDIUM"   -> 3;
            case "LOW"      -> 2;
            case "INFO"     -> 1;
            default         -> 0;
        };
    }
}
