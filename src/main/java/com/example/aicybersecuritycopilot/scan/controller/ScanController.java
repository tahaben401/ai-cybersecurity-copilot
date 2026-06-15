package com.example.aicybersecuritycopilot.scan.controller;

import com.example.aicybersecuritycopilot.scan.dto.ScanRequest;
import com.example.aicybersecuritycopilot.scan.dto.ScanResponse;
import com.example.aicybersecuritycopilot.scan.dto.ScanSummaryResponse;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.service.ScanQueryService;
import com.example.aicybersecuritycopilot.scan.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scans")
@RequiredArgsConstructor
public class ScanController {

    private final ScanService scanService;
    private final ScanQueryService scanQueryService;

    /**
     * Submit a new scan for a project. Returns the Scan ID immediately while processing asynchronously.
     */
    @PostMapping
    public ResponseEntity<ScanResponse> submitScan(@RequestBody ScanRequest request) {
        Scan scan = scanService.initiateScan(request.getProjectId(), request.getBranch());
        
        ScanResponse response = ScanResponse.builder()
                .scanId(scan.getId())
                .projectId(scan.getProject().getId())
                .status(scan.getStatus())
                .branch(scan.getBranch())
                .startedAt(scan.getStartedAt())
                .build();
                
        // HTTP 202 Accepted indicates the request is accepted for processing, but not yet completed.
        return ResponseEntity.accepted().body(response);
    }

    /** Scan status + finding counts. Polled by the frontend while a scan runs. */
    @GetMapping("/{scanId}")
    public ResponseEntity<ScanSummaryResponse> getScan(@PathVariable UUID scanId) {
        return ResponseEntity.ok(scanQueryService.getScanSummary(scanId));
    }

    /** All scans owned by a user, newest first (dashboard feed). */
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<ScanSummaryResponse>> getUserScans(@PathVariable UUID userId) {
        return ResponseEntity.ok(scanQueryService.getUserScans(userId));
    }

    /** Server-Sent Events stream of live scan progress. */
    @GetMapping(value = "/{scanId}/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamScan(@PathVariable UUID scanId) {
        return scanService.subscribeToScan(scanId);
    }
}
