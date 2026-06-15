package com.example.aicybersecuritycopilot.ai.service;

import com.example.aicybersecuritycopilot.ai.client.AiServiceClient;
import com.example.aicybersecuritycopilot.ai.entity.AiAnalysis;
import com.example.aicybersecuritycopilot.ai.repository.AiAnalysisRepository;
import com.example.aicybersecuritycopilot.finding.model.Finding;
import com.example.aicybersecuritycopilot.finding.repository.FindingRepository;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Orchestrates AI analysis of findings: builds the request the Python service
 * expects, forwards it through {@link AiServiceClient}, and caches the result so
 * a finding is only ever analysed once (unless explicitly re-run).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AiAnalysisService {

    private final FindingRepository findingRepository;
    private final AiAnalysisRepository aiAnalysisRepository;
    private final AiServiceClient aiServiceClient;
    private final ObjectMapper objectMapper;

    /**
     * Analyse a finding with the AI pipeline. Returns the cached result when one
     * already exists and {@code force} is false.
     */
    @Transactional
    public JsonNode analyzeFinding(UUID findingId, boolean force) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));

        if (!force) {
            Optional<AiAnalysis> cached = aiAnalysisRepository.findByFindingId(findingId);
            if (cached.isPresent()) {
                return readTree(cached.get().getResultJson());
            }
        }

        Scan scan = finding.getScan();
        UUID scanId = scan.getId();
        UUID projectId = scan.getProject().getId();

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("scan_id", scanId.toString());
        request.put("project_id", projectId.toString());
        request.put("finding", toFindingPayload(finding));

        log.info("Requesting AI analysis for finding {} (rule {})", findingId, finding.getRuleId());
        JsonNode result = aiServiceClient.analyze(request);

        persist(findingId, scanId, projectId, result);
        return result;
    }

    @Transactional(readOnly = true)
    public Optional<JsonNode> getCachedAnalysis(UUID findingId) {
        return aiAnalysisRepository.findByFindingId(findingId)
                .map(a -> readTree(a.getResultJson()));
    }

    @Transactional(readOnly = true)
    public List<JsonNode> getScanAnalyses(UUID scanId) {
        return aiAnalysisRepository.findByScanId(scanId).stream()
                .map(a -> readTree(a.getResultJson()))
                .toList();
    }

    private void persist(UUID findingId, UUID scanId, UUID projectId, JsonNode result) {
        AiAnalysis entity = aiAnalysisRepository.findByFindingId(findingId)
                .orElseGet(() -> AiAnalysis.builder().findingId(findingId).build());
        entity.setScanId(scanId);
        entity.setProjectId(projectId);
        entity.setStatus(result.path("overall_status").asString("GENERATED"));
        entity.setResultJson(result.toString());
        aiAnalysisRepository.save(entity);
    }

    /** Maps the JPA entity to the camelCase payload the AI {@code Finding} schema accepts. */
    private Map<String, Object> toFindingPayload(Finding f) {
        Map<String, Object> map = new LinkedHashMap<>();
        // ruleId / toolName / severity are required (min_length=1, enum) on the AI side.
        // Never forward null/blank or a single bad finding fails the whole request with a 422.
        map.put("ruleId", orDefault(f.getRuleId(), "UNKNOWN_RULE"));
        map.put("toolName", orDefault(f.getToolName(), "UNKNOWN"));
        map.put("severity", orDefault(f.getSeverity(), "MEDIUM"));
        map.put("message", f.getMessage() != null ? f.getMessage() : "");
        map.put("filePath", f.getFilePath() != null ? f.getFilePath() : "");
        map.put("startLine", Math.max(f.getStartLine(), 0));
        map.put("endLine", Math.max(f.getEndLine(), 0));
        map.put("startColumn", 0);
        map.put("endColumn", 0);
        map.put("cweId", f.getCweId());
        map.put("owaspCategory", f.getOwaspCategory());
        map.put("snippet", f.getSnippet());
        map.put("fingerprint", f.getFingerprint());
        map.put("ruleDescription", f.getRuleDescription());
        map.put("suggestedFix", f.getSuggestedFix());
        return map;
    }

    /** Returns {@code value} when present and non-blank, otherwise {@code fallback}. */
    private String orDefault(String value, String fallback) {
        return (value != null && !value.isBlank()) ? value : fallback;
    }

    private JsonNode readTree(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("Corrupted AI analysis payload", e);
        }
    }
}
