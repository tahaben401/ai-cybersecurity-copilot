package com.example.aicybersecuritycopilot.scanner;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ScannerResult {
    private final String toolName;
    private final int exitCode;
    private final String sarifContent;
    private final long executionTimeMs;
    private final boolean success;
    private final int findingsCount;
    private final String errorMessage;
}
