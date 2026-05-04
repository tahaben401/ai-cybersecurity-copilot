package com.example.aicybersecuritycopilot.scan.service;

import com.example.aicybersecuritycopilot.finding.service.FindingService;
import com.example.aicybersecuritycopilot.project.model.Project;
import com.example.aicybersecuritycopilot.project.repository.ProjectRepository;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.entity.ScanStatus;
import com.example.aicybersecuritycopilot.scan.repository.ScanRepository;
import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;
import com.example.aicybersecuritycopilot.scanner.codeql.CodeqlScanner;
import com.example.aicybersecuritycopilot.scanner.sarif.FindingDTO;
import com.example.aicybersecuritycopilot.scanner.sarif.SarifParser;
import com.example.aicybersecuritycopilot.scanner.semgrep.SemgrepScanner;
import com.example.aicybersecuritycopilot.scanner.trivy.TrivyScanner;
import com.example.aicybersecuritycopilot.broker.service.ScanResultPublisher;
import com.example.aicybersecuritycopilot.broker.dto.ScanResultMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanService {

    private final ScanRepository scanRepository;
    private final ProjectRepository projectRepository;
    private final RepoValidator repoValidator;
    private final RepoCloner repoCloner;
    private final SemgrepScanner semgrepScanner;
    private final TrivyScanner trivyScanner;
    private final CodeqlScanner codeqlScanner;
    private final SarifParser sarifParser;
    private final FindingService findingService;
    private final ScanResultPublisher scanResultPublisher;
    private final Map<UUID, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    /**
     * Sync method called by the Controller. Sets up the DB record and kicks off the Async task.
     */
    @Transactional
    public Scan initiateScan(UUID projectId, String branch) {
        // We assume Taha's project endpoints created this project earlier
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found: " + projectId));

        if (!repoValidator.isValidGithubUrl(project.getRepoUrl())) {
            throw new IllegalArgumentException("Invalid Github URL for project: " + project.getRepoUrl());
        }

        Scan scan = Scan.builder()
                .project(project)
                .status(ScanStatus.PENDING)
                .branch(branch != null ? branch : "main")
                .build();

        scan = scanRepository.save(scan);
        
        // Launch async process in a background thread
        performAsyncScan(scan.getId(), project.getRepoUrl());
        
        return scan;
    }

    /**
     * Async method running in the background. Does not block the HTTP request.
     */
    @Async
    public CompletableFuture<Void> performAsyncScan(UUID scanId, String repoUrl) {
        log.info("Starting async scan for scanId: {}", scanId);

        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.IN_PROGRESS);
        scanRepository.save(scan);

        try {
            // 1. Clone Repo
            sendUpdate(scanId, Map.of("status", "CLONING", "message", "Cloning repository..."));
            Path clonedDir = repoCloner.cloneRepository(repoUrl, scanId);

            // 2. TODO: Run CompletableFuture.allOf() for Semgrep, CodeQL, and Trivy
            sendUpdate(scanId, Map.of("status", "SCANNING", "message", "Running security engines..."));
            CompletableFuture<ScannerResult> semgrepFuture = runScannerAsync(semgrepScanner, clonedDir);
            CompletableFuture<ScannerResult> trivyFuture   = runScannerAsync(trivyScanner,   clonedDir);
            CompletableFuture<ScannerResult> codeQLFuture  = runScannerAsync(codeqlScanner,  clonedDir);
            // waiting all of them to finish
            CompletableFuture.allOf(semgrepFuture, trivyFuture, codeQLFuture).join();
            // log.info("Simulating Scanning Engines running in parallel...");
            Map<String, String> sarifOutputs = new LinkedHashMap<>();
            ScannerResult semgrepResult = semgrepFuture.getNow(failedResult(semgrepScanner.getToolName()));
            ScannerResult trivyResult   = trivyFuture.getNow(failedResult(trivyScanner.getToolName()));
            ScannerResult codeQLResult  = codeQLFuture.getNow(failedResult(codeqlScanner.getToolName()));

            if (semgrepResult.isSuccess() && semgrepResult.getSarifContent() != null) {
                sarifOutputs.put(semgrepResult.getToolName(), semgrepResult.getSarifContent());
            }
            if (trivyResult.isSuccess() && trivyResult.getSarifContent() != null) {
                sarifOutputs.put(trivyResult.getToolName(), trivyResult.getSarifContent());
            }
            if (codeQLResult.isSuccess() && codeQLResult.getSarifContent() != null) {
                sarifOutputs.put(codeQLResult.getToolName(), codeQLResult.getSarifContent());
            }

            List<FindingDTO> findings = sarifParser.parseAndMerge(sarifOutputs);
            log.info("Total merged findings after deduplication: {}", findings.size());

            // Log per-scanner summary
            log.info("[Semgrep] success: {}, findings: {}, time: {}ms",
                    semgrepResult.isSuccess(), semgrepResult.getFindingsCount(), semgrepResult.getExecutionTimeMs());
            log.info("[Trivy]   success: {}, findings: {}, time: {}ms",
                    trivyResult.isSuccess(), trivyResult.getFindingsCount(), trivyResult.getExecutionTimeMs());
            log.info("[CodeQL]  success: {}, findings: {}, time: {}ms",
                    codeQLResult.isSuccess(), codeQLResult.getFindingsCount(), codeQLResult.getExecutionTimeMs());

            // 3. Mark complete
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setFinishedAt(LocalDateTime.now());
            findingService.saveFindings(scanId, findings);
            scanRepository.save(scan);

            // Send to RabbitMQ for AI Service
            ScanResultMessage message = ScanResultMessage.builder()
                    .scanId(scanId)
                    .projectId(scan.getProject().getId())
                    .branch(scan.getBranch())
                    .findings(findings)
                    .build();
            scanResultPublisher.publishScanResults(message);

            // 4. Cleanup to save space
            repoCloner.cleanupRepository(scanId);

            log.info("Async scan completed successfully for scanId: {}", scanId);
            sendUpdate(scanId, Map.of("status", "COMPLETED", "scanId", scanId));
            // Close all emitters for this scan
            List<SseEmitter> scanEmitters = emitters.remove(scanId);
            if (scanEmitters != null) {
                scanEmitters.forEach(SseEmitter::complete);
            }
            return CompletableFuture.completedFuture(null);

        } catch (Exception e) {
            log.error("Scan failed for scanId: {}", scanId, e);
            scan.setStatus(ScanStatus.FAILED);
            scan.setFinishedAt(LocalDateTime.now());
            scanRepository.save(scan);
            sendUpdate(scanId, Map.of("status", "FAILED", "error", e.getMessage()));
            // Always cleanup on fail!
            repoCloner.cleanupRepository(scanId);
            // Close all emitters for this scan
            List<SseEmitter> scanEmitters = emitters.remove(scanId);
            if (scanEmitters != null) {
                scanEmitters.forEach(SseEmitter::complete);
            }
            return CompletableFuture.failedFuture(e);
        }
    }
    private CompletableFuture<ScannerResult> runScannerAsync(SecurityScanner scanner, Path repoPath) {
        return CompletableFuture.supplyAsync(() -> {
            if (!scanner.isAvailable()) {
                log.warn("[{}] Scanner not available, skipping.", scanner.getToolName());
                return failedResult(scanner.getToolName());
            }
            try {
                return scanner.scan(repoPath);
            } catch (ScannerExecutionException e) {
                log.error("[{}] Scanner threw exception: {}", scanner.getToolName(), e.getMessage());
                return failedResult(scanner.getToolName());
            }
        });
    }
    public SseEmitter subscribeToScan(UUID scanId) {
        // 5-minute timeout for the stream
        SseEmitter emitter = new SseEmitter(300_000L);

        this.emitters.computeIfAbsent(scanId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(scanId, emitter));
        emitter.onTimeout(() -> removeEmitter(scanId, emitter));
        emitter.onError((e) -> removeEmitter(scanId, emitter));

        return emitter;
    }

    private void removeEmitter(UUID scanId, SseEmitter emitter) {
        List<SseEmitter> scanEmitters = emitters.get(scanId);
        if (scanEmitters != null) {
            scanEmitters.remove(emitter);
            if (scanEmitters.isEmpty()) emitters.remove(scanId);
        }
    }

    private void sendUpdate(UUID scanId, Object data) {
        List<SseEmitter> scanEmitters = emitters.get(scanId);
        if (scanEmitters != null) {
            for (SseEmitter emitter : scanEmitters) {
                try {
                    emitter.send(SseEmitter.event()
                            .name("scan-update")
                            .data(data));
                } catch (Exception e) {
                    removeEmitter(scanId, emitter);
                }
            }
        }
    }

    private ScannerResult failedResult(String toolName) {
        return ScannerResult.builder()
                .toolName(toolName)
                .success(false)
                .findingsCount(0)
                .errorMessage("Scanner unavailable or failed")
                .build();
    }
}
