package com.example.aicybersecuritycopilot.scanner.semgrep;

import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
/*hna khdemt b ProcessBuilder bach tape la commande automatiquement (commande dial lancement d semgrep)  */
 /*w cerveau howa sarifParser danc dak sarif genere b semgrep kbir bzaf danc hna kanhtajo sarif parser */
@Service
@RequiredArgsConstructor
@Slf4j
public class SemgrepScanner implements SecurityScanner {

    private static final String TOOL_NAME = "Semgrep";
    private final SemgrepProperties properties;

    @Override
    public ScannerResult scan(Path codeDirectory) throws ScannerExecutionException {
        validatePreconditions(codeDirectory);

        Path sarifOutputFile = createTempSarifFile();
        List<String> command = buildCommand(codeDirectory, sarifOutputFile);

        log.info("[{}] Starting scan on: {}", TOOL_NAME, codeDirectory);
        long startTime = System.currentTimeMillis();

        try {
            int exitCode = executeProcess(command, codeDirectory);
            long executionTimeMs = System.currentTimeMillis() - startTime;
            return handleProcessResult(exitCode, sarifOutputFile, executionTimeMs);
        } catch (ScannerExecutionException e) {
            throw e;
        } catch (Exception e) {
            long executionTimeMs = System.currentTimeMillis() - startTime;
            log.error("[{}] Unexpected error after {}ms", TOOL_NAME, executionTimeMs, e);
            throw new ScannerExecutionException(TOOL_NAME, "Unexpected scan failure", e);
        } finally {
            cleanupTempFile(sarifOutputFile);
        }
    }

    @Override
    public String getToolName() {
        return TOOL_NAME;
    }

    @Override
    public boolean isAvailable() {
        try {
            ProcessBuilder pb = new ProcessBuilder("semgrep", "--version");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            boolean finished = process.waitFor(10, TimeUnit.SECONDS);

            if (finished && process.exitValue() == 0) {
                return true;
            }
            return false;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return false;
        }
    }

    private List<String> buildCommand(Path codeDirectory, Path sarifOutputFile) {
        List<String> command = new ArrayList<>();
        command.add("semgrep");
        command.add("scan");

        for (String ruleset : properties.getRulesets()) {
            command.add("--config");
            command.add(ruleset);
        }

        command.add("--sarif");
        command.add("--output");
        command.add(sarifOutputFile.toAbsolutePath().toString());

        for (String excludedDir : properties.getExcludedDirs()) {
            command.add("--exclude");
            command.add(excludedDir);
        }

        command.add("--max-target-bytes");
        command.add(String.valueOf(properties.getMaxFileSizeBytes()));

        if (!properties.isMetricsEnabled()) {
            command.add("--metrics=off");
        }

        command.add("--quiet");
        command.add(codeDirectory.toAbsolutePath().toString());

        return command;
    }

    private int executeProcess(List<String> command, Path workingDir) throws ScannerExecutionException {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(workingDir.toFile());
            pb.redirectErrorStream(true);

            Process process = pb.start();
            String processOutput = drainProcessOutput(process);
            boolean finished = process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new ScannerExecutionException(TOOL_NAME, "Scan timed out");
            }

            int exitCode = process.exitValue();
            if (exitCode >= 2) {
                log.error("[{}] Process failed with exit code {}. Output:\n{}", TOOL_NAME, exitCode, truncate(processOutput));
            }

            return exitCode;
        } catch (IOException e) {
            throw new ScannerExecutionException(TOOL_NAME, "Failed to start process", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScannerExecutionException(TOOL_NAME, "Process interrupted", e);
        }
    }

    private ScannerResult handleProcessResult(int exitCode, Path sarifOutputFile, long executionTimeMs) {
        if (exitCode >= 2) {
            return ScannerResult.builder()
                    .toolName(TOOL_NAME)
                    .exitCode(exitCode)
                    .executionTimeMs(executionTimeMs)
                    .success(false)
                    .errorMessage("Semgrep exited with error code: " + exitCode)
                    .build();
        }

        String sarifContent = readSarifFile(sarifOutputFile);
        int findingsCount = countFindingsQuick(sarifContent);

        return ScannerResult.builder()
                .toolName(TOOL_NAME)
                .exitCode(exitCode)
                .sarifContent(sarifContent)
                .executionTimeMs(executionTimeMs)
                .success(true)
                .findingsCount(findingsCount)
                .build();
    }

    private void validatePreconditions(Path codeDirectory) {
        if (!properties.isEnabled()) throw new ScannerExecutionException(TOOL_NAME, "Scanner disabled");
        if (codeDirectory == null || !Files.isDirectory(codeDirectory)) throw new ScannerExecutionException(TOOL_NAME, "Invalid directory");
        if (!isAvailable()) throw new ScannerExecutionException(TOOL_NAME, "Semgrep CLI not installed");
    }

    private Path createTempSarifFile() {
        try {
            return Files.createTempFile("mantis-semgrep-", ".sarif");
        } catch (IOException e) {
            throw new ScannerExecutionException(TOOL_NAME, "Cannot create temp file", e);
        }
    }

    private String readSarifFile(Path sarifFile) {
        try {
            if (!Files.exists(sarifFile) || Files.size(sarifFile) == 0) return "{}";
            return Files.readString(sarifFile);
        } catch (IOException e) {
            throw new ScannerExecutionException(TOOL_NAME, "Failed to read SARIF", e);
        }
    }


    private void cleanupTempFile(Path file) {
        try { Files.deleteIfExists(file); } catch (IOException ignored) {}
    }

    private int countFindingsQuick(String sarifContent) {
        if (sarifContent == null || sarifContent.isBlank()) return 0;
        int count = 0, index = 0;
        while ((index = sarifContent.indexOf("\"ruleId\"", index)) != -1) { count++; index++; }
        return count;
    }

    private String drainProcessOutput(Process process) throws IOException {
        return new String(process.getInputStream().readAllBytes());
    }

    private String truncate(String text) {
        if (text == null) return "";
        return text.length() > 2000 ? text.substring(0, 2000) + "\n... [TRUNCATED]" : text;
    }
}
