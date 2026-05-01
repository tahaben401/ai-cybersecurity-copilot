package com.example.aicybersecuritycopilot.scan.service;

import com.example.aicybersecuritycopilot.project.model.Project;
import com.example.aicybersecuritycopilot.project.repository.ProjectRepository;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.entity.ScanStatus;
import com.example.aicybersecuritycopilot.scan.repository.ScanRepository;
import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;
import com.example.aicybersecuritycopilot.scanner.codeql.CodeqlScanner;
import com.example.aicybersecuritycopilot.scanner.semgrep.SemgrepScanner;
import com.example.aicybersecuritycopilot.scanner.trivy.TrivyScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

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
            Path clonedDir = repoCloner.cloneRepository(repoUrl, scanId);
            
            // 2. TODO: Run CompletableFuture.allOf() for Semgrep, CodeQL, and Trivy
            CompletableFuture<ScannerResult> semgrepFuture = runScannerAsync(semgrepScanner, clonedDir);
            CompletableFuture<ScannerResult> trivyFuture   = runScannerAsync(trivyScanner,   clonedDir);
            CompletableFuture<ScannerResult> codeQLFuture  = runScannerAsync(codeqlScanner,  clonedDir);
            // waiting all of them to finish
            CompletableFuture.allOf(semgrepFuture, trivyFuture, codeQLFuture).join();
            // log.info("Simulating Scanning Engines running in parallel...");

            //Thread.sleep(3000);
            List<ScannerResult> results = List.of(
                    semgrepFuture.getNow(failedResult(semgrepScanner.getToolName())),
                    trivyFuture.getNow(failedResult(trivyScanner.getToolName())),
                    codeQLFuture.getNow(failedResult(codeqlScanner.getToolName()))
            );

            results.forEach(r -> log.info("[{}] findings: {}, success: {}, time: {}ms",
                    r.getToolName(), r.getFindingsCount(), r.isSuccess(), r.getExecutionTimeMs()));
            // 3. Mark complete
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setFinishedAt(LocalDateTime.now());
            scanRepository.save(scan);
            
            // 4. Cleanup to save space
            repoCloner.cleanupRepository(scanId);
            
            log.info("Async scan completed successfully for scanId: {}", scanId);
            return CompletableFuture.completedFuture(null);
            
        } catch (Exception e) {
            log.error("Scan failed for scanId: {}", scanId, e);
            scan.setStatus(ScanStatus.FAILED);
            scan.setFinishedAt(LocalDateTime.now());
            scanRepository.save(scan);
            
            // Always cleanup on fail!
            repoCloner.cleanupRepository(scanId);
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

    private ScannerResult failedResult(String toolName) {
        return ScannerResult.builder()
                .toolName(toolName)
                .success(false)
                .findingsCount(0)
                .errorMessage("Scanner unavailable or failed")
                .build();
    }
}
