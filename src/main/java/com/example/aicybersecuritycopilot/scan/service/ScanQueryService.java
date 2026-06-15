package com.example.aicybersecuritycopilot.scan.service;

import com.example.aicybersecuritycopilot.finding.repository.FindingRepository;
import com.example.aicybersecuritycopilot.scan.dto.ScanSummaryResponse;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.repository.ScanRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Read-side queries for scans. Kept separate from {@link ScanService} (which owns
 * the heavyweight async scan lifecycle) so the read model stays simple and cheap.
 */
@Service
@RequiredArgsConstructor
public class ScanQueryService {

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;

    @Transactional(readOnly = true)
    public ScanSummaryResponse getScanSummary(UUID scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new EntityNotFoundException("Scan not found: " + scanId));

        Map<String, Long> severity = toSeverityMap(findingRepository.countSeverityByScan(scanId));
        return toSummary(scan, severity);
    }

    @Transactional(readOnly = true)
    public List<ScanSummaryResponse> getProjectScans(UUID projectId) {
        return enrich(scanRepository.findByProjectIdOrderByStartedAtDesc(projectId));
    }

    @Transactional(readOnly = true)
    public List<ScanSummaryResponse> getUserScans(UUID userId) {
        return enrich(scanRepository.findByProject_User_IdOrderByStartedAtDesc(userId));
    }

    /** Attaches per-scan severity counts using a single grouped query. */
    private List<ScanSummaryResponse> enrich(List<Scan> scans) {
        if (scans.isEmpty()) {
            return List.of();
        }
        List<UUID> ids = scans.stream().map(Scan::getId).toList();
        Map<UUID, Map<String, Long>> bySeverity = new HashMap<>();
        for (Object[] row : findingRepository.countSeverityByScans(ids)) {
            UUID scanId = (UUID) row[0];
            String sev = (String) row[1];
            long count = ((Number) row[2]).longValue();
            bySeverity.computeIfAbsent(scanId, k -> new HashMap<>()).put(normalize(sev), count);
        }
        return scans.stream()
                .map(scan -> toSummary(scan, bySeverity.getOrDefault(scan.getId(), Map.of())))
                .toList();
    }

    private Map<String, Long> toSeverityMap(List<Object[]> rows) {
        Map<String, Long> map = new HashMap<>();
        for (Object[] row : rows) {
            map.put(normalize((String) row[0]), ((Number) row[1]).longValue());
        }
        return map;
    }

    private ScanSummaryResponse toSummary(Scan scan, Map<String, Long> severity) {
        long total = severity.values().stream().mapToLong(Long::longValue).sum();
        return ScanSummaryResponse.builder()
                .scanId(scan.getId())
                .projectId(scan.getProject().getId())
                .projectName(scan.getProject().getName())
                .repoUrl(scan.getProject().getRepoUrl())
                .status(scan.getStatus())
                .branch(scan.getBranch())
                .startedAt(scan.getStartedAt())
                .finishedAt(scan.getFinishedAt())
                .durationMs(scan.getDurationMs())
                .findingsCount(total)
                .criticalCount(severity.getOrDefault("CRITICAL", 0L))
                .highCount(severity.getOrDefault("HIGH", 0L))
                .mediumCount(severity.getOrDefault("MEDIUM", 0L))
                .lowCount(severity.getOrDefault("LOW", 0L))
                .infoCount(severity.getOrDefault("INFO", 0L))
                .scanners(scan.getScannerRuns())
                .build();
    }

    private String normalize(String severity) {
        return severity == null ? "INFO" : severity.toUpperCase().trim();
    }
}
