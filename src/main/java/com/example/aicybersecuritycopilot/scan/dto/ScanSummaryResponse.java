package com.example.aicybersecuritycopilot.scan.dto;

import com.example.aicybersecuritycopilot.scan.entity.ScanStatus;
import com.example.aicybersecuritycopilot.scan.entity.ScannerRun;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Read-oriented view of a Scan, enriched with finding counts so the frontend
 * can render dashboards and scan lists without an N+1 round trip.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanSummaryResponse {
    private UUID scanId;
    private UUID projectId;
    private String projectName;
    private String repoUrl;
    private ScanStatus status;
    private String branch;
    private LocalDateTime startedAt;
    private LocalDateTime finishedAt;
    private Integer durationMs;

    private long findingsCount;
    private long criticalCount;
    private long highCount;
    private long mediumCount;
    private long lowCount;
    private long infoCount;

    /** Per-scanner outcome (Semgrep / CodeQL / Trivy): success, findings, duration, error. */
    private List<ScannerRun> scanners;
}
