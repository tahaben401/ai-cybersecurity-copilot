package com.example.aicybersecuritycopilot.finding.service;

import com.example.aicybersecuritycopilot.finding.dto.FindingResponse;
import com.example.aicybersecuritycopilot.finding.repository.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class FindingQueryService {

    private final FindingRepository findingRepository;

    @Transactional(readOnly = true)
    public List<FindingResponse> getFindingsForScan(UUID scanId) {
        return findingRepository.findByScanIdOrderBySeverityAsc(scanId).stream()
                .map(FindingResponse::fromEntity)
                .toList();
    }
}
