package com.example.aicybersecuritycopilot.scanner.sarif;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class FindingDTO {
    private final String ruleId;
    private final String toolName;
    private final String severity;
    private final String message;
    private final String filePath;
    private final int startLine;
    private final int endLine;
    private final int startColumn;
    private final int endColumn;
    private final String cweId;
    private final String owaspCategory;
    private final String snippet;
    private final String fingerprint;
    private final String ruleDescription;
    private final String suggestedFix;
}
