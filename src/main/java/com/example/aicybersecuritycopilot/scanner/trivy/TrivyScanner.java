package com.example.aicybersecuritycopilot.scanner.trivy;

import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrivyScanner implements SecurityScanner {
    private static final String TOOL_NAME = "Trivy";
    private final TrivyProperties properties;

    private boolean isRuntimeAvailable = false;

    @PostConstruct
    public void verifyAvailability() {
        if (properties.isEnabled()) {
            if (isAvailable()) {
                this.isRuntimeAvailable = true;
                log.info("[{}] Scanner is ready.", TOOL_NAME);
            } else {
                log.warn("[{}] CLI not found or unresponsive – disabling scanner.", TOOL_NAME);
            }
        }
    }

    @Override
    public ScannerResult scan(Path codeDirectory) throws ScannerExecutionException {
        if (!properties.isEnabled() || !isRuntimeAvailable) {
            throw new ScannerExecutionException(TOOL_NAME, "Scanner is inactive.");
        }

        Path sarifOutputFile = createTempSarifFile();
        List<String> command = buildCommand(codeDirectory, sarifOutputFile);

        long startTime = System.currentTimeMillis();
        try {
            int exitCode = executeProcess(command, codeDirectory);
            long executionTimeMs = System.currentTimeMillis() - startTime;

            return handleProcessResult(exitCode, sarifOutputFile, executionTimeMs);
        } finally {
            cleanupTempFile(sarifOutputFile);
        }
    }

    private int executeProcess(List<String> command, Path workingDir) throws ScannerExecutionException {
        Process process = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(workingDir.toFile());
            pb.redirectErrorStream(true);

            process = pb.start();

            // FIX: Async drain to prevent process hanging while waiting for timeout
            CompletableFuture<String> outputFuture = drainAsync(process);

            boolean finished = process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new ScannerExecutionException(TOOL_NAME, "Scan timed out");
            }

            int exitCode = process.exitValue();
            if (exitCode >= 2) {
                log.error("[{}] Error exit ({}). Output: {}", TOOL_NAME, exitCode, truncate(outputFuture.getNow("")));
            }
            return exitCode;
        } catch (IOException | InterruptedException e) {
            if (process != null) process.destroyForcibly();
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new ScannerExecutionException(TOOL_NAME, "Execution failed", e);
        }
    }

    private ScannerResult handleProcessResult(int exitCode, Path sarifOutputFile, long executionTimeMs) {
        // Trivy returns 1 if findings exist (due to --exit-code 1), 0 if clean.
        // 2 or higher indicates a crash/logic error.
        if (exitCode >= 2) {
            return ScannerResult.builder()
                    .toolName(TOOL_NAME).exitCode(exitCode).executionTimeMs(executionTimeMs)
                    .success(false).errorMessage("Trivy failed with code " + exitCode).build();
        }

        String sarifContent = readSarifFile(sarifOutputFile);
        int findingsCount = countFindingsQuick(sarifContent);

        return ScannerResult.builder()
                .toolName(TOOL_NAME).exitCode(exitCode).sarifContent(sarifContent)
                .executionTimeMs(executionTimeMs).success(true).findingsCount(findingsCount).build();
    }

    /**
     * Optimized string-based counting.
     * Ignores rule definitions by only searching after the "results" block begins.
     */
    private int countFindingsQuick(String sarifContent) {
        if (sarifContent == null || sarifContent.isBlank()) return 0;

        // In SARIF, actual vulnerabilities are listed in the "results" array.
        // Rule descriptions (definitions) are listed in the "rules" array.
        int resultsStartIndex = sarifContent.indexOf("\"results\":");
        if (resultsStartIndex == -1) return 0;

        int count = 0;
        int index = resultsStartIndex;
        while ((index = sarifContent.indexOf("\"ruleId\"", index)) != -1) {
            count++;
            index += 8; // move past "ruleId"
        }
        return count;
    }

    @Override
    public boolean isAvailable() {
        Process process = null;
        try {
            List<String> command = new ArrayList<>(getOsCommand("trivy"));
            command.add("--version");
            process = new ProcessBuilder(command).start();
            drainAsync(process);
            return process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
    }

    private List<String> buildCommand(Path codeDirectory, Path sarifOutputFile) {
        List<String> command = new ArrayList<>();
        command.addAll(getOsCommand("trivy"));
        command.addAll(List.of("fs", "--format", "sarif", "--output", sarifOutputFile.toString(),
                "--exit-code", "1", "--severity", "HIGH,CRITICAL", codeDirectory.toString()));
        return command;
    }

    private CompletableFuture<String> drainAsync(Process process) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) { return ""; }
        });
    }

    private Path createTempSarifFile() {
        try { return Files.createTempFile("trivy-scan-", ".sarif"); }
        catch (IOException e) { throw new ScannerExecutionException(TOOL_NAME, "Temp file error", e); }
    }

    private void cleanupTempFile(Path file) {
        try { if (file != null) Files.deleteIfExists(file); } catch (IOException ignored) {}
    }

    private String readSarifFile(Path sarifFile) {
        try {
            if (!Files.exists(sarifFile) || Files.size(sarifFile) == 0) return "{}";
            return Files.readString(sarifFile, StandardCharsets.UTF_8);
        } catch (IOException e) { throw new ScannerExecutionException(TOOL_NAME, "Read error", e); }
    }

    private String truncate(String text) {
        return (text != null && text.length() > 1000) ? text.substring(0, 1000) + "..." : text;
    }

    @Override
    public String getToolName() { return TOOL_NAME; }

    private List<String> getOsCommand(String baseCommand) {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return List.of("cmd.exe", "/c", baseCommand);
        }
        return List.of(baseCommand);
    }
}