package com.example.aicybersecuritycopilot.finding.controller;

import com.example.aicybersecuritycopilot.finding.dto.FindingResponse;
import com.example.aicybersecuritycopilot.finding.service.FindingQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
public class FindingController {

    private final FindingQueryService findingQueryService;

    @GetMapping("/{scanId}/findings")
    public ResponseEntity<List<FindingResponse>> getFindings(@PathVariable UUID scanId) {
        return ResponseEntity.ok(findingQueryService.getFindingsForScan(scanId));
    }
}
