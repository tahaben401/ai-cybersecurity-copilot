package com.example.aicybersecuritycopilot.ai.controller;

import com.example.aicybersecuritycopilot.ai.client.AiServiceClient;
import com.example.aicybersecuritycopilot.ai.service.AiAnalysisService;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Frontend-facing endpoints for AI-assisted vulnerability analysis.
 * All AI traffic is proxied through here so credentials stay server-side.
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AiController {

    private final AiAnalysisService aiAnalysisService;
    private final AiServiceClient aiServiceClient;

    /** Trigger (or re-run with ?force=true) AI analysis for a single finding. */
    @PostMapping("/findings/{findingId}/analyze")
    public ResponseEntity<JsonNode> analyzeFinding(
            @PathVariable UUID findingId,
            @RequestParam(defaultValue = "false") boolean force) {
        return ResponseEntity.ok(aiAnalysisService.analyzeFinding(findingId, force));
    }

    /** Fetch a previously computed AI analysis for a finding, if any. */
    @GetMapping("/findings/{findingId}/analyze")
    public ResponseEntity<JsonNode> getFindingAnalysis(@PathVariable UUID findingId) {
        return aiAnalysisService.getCachedAnalysis(findingId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    /** All AI analyses produced for a given scan. */
    @GetMapping("/scans/{scanId}/ai-results")
    public ResponseEntity<List<JsonNode>> getScanAnalyses(@PathVariable UUID scanId) {
        return ResponseEntity.ok(aiAnalysisService.getScanAnalyses(scanId));
    }

    /** Lightweight reachability check for the AI service, surfaced in the UI. */
    @GetMapping("/ai/health")
    public ResponseEntity<Map<String, Object>> aiHealth() {
        boolean up = aiServiceClient.isHealthy();
        return ResponseEntity.ok(Map.of("status", up ? "UP" : "DOWN"));
    }
}
