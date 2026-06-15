package com.example.aicybersecuritycopilot.finding.dto;

import com.example.aicybersecuritycopilot.finding.model.Finding;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

/**
 * Flat, serialization-safe representation of a {@link Finding}.
 * Mapping to this DTO avoids dragging the lazily-loaded Scan/Project graph
 * into the JSON response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FindingResponse {
    private UUID id;
    private UUID scanId;
    private String toolName;
    private String ruleId;
    private String severity;
    private String message;
    private String filePath;
    private int startLine;
    private int endLine;
    private String cweId;
    private String owaspCategory;
    private String snippet;
    private String ruleDescription;
    private String suggestedFix;
    private String fingerprint;

    public static FindingResponse fromEntity(Finding f) {
        return FindingResponse.builder()
                .id(f.getId())
                .scanId(f.getScan() != null ? f.getScan().getId() : null)
                .toolName(f.getToolName())
                .ruleId(f.getRuleId())
                .severity(f.getSeverity())
                .message(f.getMessage())
                .filePath(f.getFilePath())
                .startLine(f.getStartLine())
                .endLine(f.getEndLine())
                .cweId(f.getCweId())
                .owaspCategory(f.getOwaspCategory())
                .snippet(f.getSnippet())
                .ruleDescription(f.getRuleDescription())
                .suggestedFix(f.getSuggestedFix())
                .fingerprint(f.getFingerprint())
                .build();
    }
}
