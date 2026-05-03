package com.example.aicybersecuritycopilot.finding.service;

import com.example.aicybersecuritycopilot.finding.model.Finding;
import com.example.aicybersecuritycopilot.finding.repository.FindingRepository;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.repository.ScanRepository;
import com.example.aicybersecuritycopilot.scanner.sarif.FindingDTO;
import com.example.aicybersecuritycopilot.scanner.sarif.SarifParser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FindingService {

    private final FindingRepository findingRepository;
    private final ScanRepository scanRepository;

    public void saveFindings(UUID scanId, List<FindingDTO> dtos) {
        Scan scan = scanRepository.getReferenceById(scanId);

        List<Finding> findings = dtos.stream()
                .map(dto -> Finding.builder()
                        .scan(scan)
                        .toolName(dto.getToolName())
                        .ruleId(dto.getRuleId())
                        .severity(dto.getSeverity())
                        .filePath(dto.getFilePath())
                        .startLine(dto.getStartLine())
                        .endLine(dto.getEndLine())
                        .message(dto.getMessage())
                        .snippet(dto.getSnippet())
                        .ruleDescription(dto.getRuleDescription())
                        .suggestedFix(dto.getSuggestedFix())
                        .cweId(dto.getCweId())
                        .owaspCategory(dto.getOwaspCategory())
                        .fingerprint(dto.getFingerprint())
                        .build())
                .toList();

        findingRepository.saveAll(findings);
        //log.info("Saved {} findings for scan {}", findings.size(), scanId);
    }
}
