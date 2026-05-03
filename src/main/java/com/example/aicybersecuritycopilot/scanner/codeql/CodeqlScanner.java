package com.example.aicybersecuritycopilot.scanner.codeql;

import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;

import jakarta.annotation.PostConstruct;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonReader;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class CodeqlScanner implements SecurityScanner {

    private static final String TOOL_NAME = "CodeQL";

    private final CodeqlProperties properties;

    @PostConstruct
    public void verifyAvailability() {
        if (properties.isEnabled() && !isAvailable())
            log.warn("[{}] CLI not found on PATH – scanner will be disabled at runtime", TOOL_NAME);
    }
    @PostConstruct
    public void downloadQueryPacks() {
        List<String> packs = List.of(
                "codeql/java-queries",
                "codeql/javascript-queries",
                "codeql/python-queries"
        );

        log.info("[CodeQL] Downloading required query packs: {}", packs);
        try {
            List<String> cmd = new ArrayList<>();
            cmd.addAll(getOsCommand("codeql"));
            cmd.add("pack");
            cmd.add("download");
            cmd.addAll(packs);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String output = new String(process.getInputStream().readAllBytes());
            int exitCode = process.waitFor();

            if (exitCode == 0) {
                log.info("[CodeQL] All query packs ready.");
            } else {
                log.warn("[CodeQL] Pack download exited with code {}. Output:\n{}", exitCode, output);
            }
        } catch (Exception e) {
            log.warn("[CodeQL] Could not download query packs: {}", e.getMessage());
        }
    }



    @Override
    public ScannerResult scan(Path codeDirectory) throws ScannerExecutionException {
        if (!properties.isEnabled())
            throw new ScannerExecutionException(TOOL_NAME, "Scanner disabled");
        if (codeDirectory == null || !Files.isDirectory(codeDirectory))
            throw new ScannerExecutionException(TOOL_NAME, "Invalid directory");

        String uniqueId = UUID.randomUUID().toString().substring(0, 8);
        Path base = properties.getDatabaseDir() != null && !properties.getDatabaseDir().isBlank()
                ? Paths.get(properties.getDatabaseDir())
                : Path.of(System.getProperty("java.io.tmpdir"));

        Path dbDir;
        Path sarifOutput;
        try {
            dbDir       = Files.createDirectories(base.resolve("mantis-codeql-db-" + uniqueId));
            sarifOutput = Files.createTempFile("mantis-codeql-", ".sarif");
        } catch (IOException e) {
            throw new ScannerExecutionException(TOOL_NAME, "Cannot create temp files", e);
        }

        log.info("[{}] Starting scan on: {}", TOOL_NAME, codeDirectory);
        long start = System.currentTimeMillis();

        try {
            String language = resolveLanguage(codeDirectory);
            buildDatabase(codeDirectory, dbDir, language);

            int exitCode = analyzeDatabase(dbDir, sarifOutput, language);
            long elapsed = System.currentTimeMillis() - start;

            if (exitCode != 0) {
                return ScannerResult.builder()
                        .toolName(TOOL_NAME).exitCode(exitCode)
                        .executionTimeMs(elapsed).success(false)
                        .errorMessage("CodeQL exited with error code: " + exitCode)
                        .build();
            }

            String sarif = Files.exists(sarifOutput) && Files.size(sarifOutput) > 0
                    ? Files.readString(sarifOutput) : "{}";

            int findingsCount = 0;
            try (JsonReader reader = Json.createReader(new StringReader(sarif))) {
                JsonArray results = reader.readObject()
                        .getJsonArray("runs").getJsonObject(0)
                        .getJsonArray("results");
                findingsCount = results != null ? results.size() : 0;
            } catch (Exception e) {
                log.warn("[{}] Could not parse SARIF to count findings, defaulting to 0", TOOL_NAME);
            }

            log.info("[{}] Scan complete in {}ms – {} finding(s)", TOOL_NAME, elapsed, findingsCount);

            return ScannerResult.builder()
                    .toolName(TOOL_NAME).exitCode(exitCode)
                    .sarifContent(sarif).executionTimeMs(elapsed)
                    .success(true).findingsCount(findingsCount)
                    .build();

        } catch (ScannerExecutionException e) {
            throw e;
        } catch (Exception e) {
            log.error("[{}] Unexpected error after {}ms", TOOL_NAME, System.currentTimeMillis() - start, e);
            throw new ScannerExecutionException(TOOL_NAME, "Unexpected scan failure", e);
        } finally {
            try { Files.deleteIfExists(sarifOutput); } catch (IOException ignored) {}
            cleanupDirectory(dbDir);
        }
    }

    @Override
    public String getToolName() { return TOOL_NAME; }

    @Override
    public boolean isAvailable() {
        try {
            List<String> command = new ArrayList<>(getOsCommand("codeql"));
            command.add("version");
            Process process = new ProcessBuilder(command)
                    .redirectErrorStream(true).start();
            drainAsync(process);
            return process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Step 1: codeql database create
    // -------------------------------------------------------------------------

    private void buildDatabase(Path codeDirectory, Path dbDir, String language) {
        List<String> cmd = new ArrayList<>();
        cmd.addAll(getOsCommand("codeql"));
        cmd.addAll(List.of("database", "create", dbDir.toAbsolutePath().toString(),
                "--language=" + language,
                "--source-root=" + codeDirectory.toAbsolutePath(),
                "--overwrite",
                "--build-mode=none"   // ← add this
        ));
        if (properties.getThreads() > 0) cmd.add("--threads=" + properties.getThreads());
        if (properties.getRamMb()   > 0) cmd.add("--ram="     + properties.getRamMb());
        //properties.getExcludedDirs().forEach(e -> cmd.add("--exclude=" + e));

        log.info("[{}] Building database for language '{}'", TOOL_NAME, language);
        int exitCode = executeProcess(cmd, codeDirectory, "database create");
        if (exitCode != 0)
            throw new ScannerExecutionException(TOOL_NAME, "Database creation failed with exit code: " + exitCode);

        log.info("[{}] Database created successfully", TOOL_NAME);
    }

    // -------------------------------------------------------------------------
    // Step 2: codeql database analyze
    // -------------------------------------------------------------------------

    private int analyzeDatabase(Path dbDir, Path sarifOutput, String language) {
        List<String> cmd = new ArrayList<>();
        cmd.addAll(getOsCommand("codeql"));
        cmd.addAll(List.of("database", "analyze", dbDir.toAbsolutePath().toString(),
                "--format=sarif-latest",
                "--output=" + sarifOutput.toAbsolutePath(),
                "--no-print-diagnostics-summary"
        ));

        // ✅ Correct pack reference format
        properties.getQuerySuites().forEach(suite ->
                cmd.add("codeql/" + language + "-queries:codeql-suites/" + language + "-" + suite + ".qls")
        );

        if (properties.getThreads() > 0) cmd.add("--threads=" + properties.getThreads());
        if (properties.getRamMb()   > 0) cmd.add("--ram="     + properties.getRamMb());

        log.info("[{}] Running analysis -> {}", TOOL_NAME, sarifOutput);
        log.info("[{}] Full analyze command: {}", TOOL_NAME, String.join(" ", cmd)); // keep this for debugging
        return executeProcess(cmd, dbDir, "database analyze");
    }
    // -------------------------------------------------------------------------
    // Process execution
    // -------------------------------------------------------------------------

    private int executeProcess(List<String> command, Path workingDir, String stepLabel) {
        try {
            Process process = new ProcessBuilder(command)
                    .directory(workingDir.toFile())
                    .redirectErrorStream(true)
                    .start();

            CompletableFuture<String> outputFuture = drainAsync(process);
            boolean finished = process.waitFor(properties.getTimeoutSeconds(), TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                throw new ScannerExecutionException(TOOL_NAME,
                        "Step '" + stepLabel + "' timed out after " + properties.getTimeoutSeconds() + "s");
            }

            int exitCode = process.exitValue();
            if (exitCode != 0) {
                String out = outputFuture.join();
                log.error("[{}] Step '{}' exited with code {}. Output:\n{}",
                        TOOL_NAME, stepLabel, exitCode,
                        out.length() > 2000 ? out.substring(0, 2000) + "\n... [TRUNCATED]" : out);
            }

            return exitCode;

        } catch (IOException e) {
            throw new ScannerExecutionException(TOOL_NAME, "Failed to start: " + stepLabel, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScannerExecutionException(TOOL_NAME, "Interrupted during: " + stepLabel, e);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private String resolveLanguage(Path codeDirectory) {
        List<String> configured = properties.getLanguages();
        if (configured != null && configured.size() == 1) {
            String lang = configured.get(0);
            if (lang != null && !lang.isBlank() && !"auto".equalsIgnoreCase(lang)) {
                return lang.trim();
            }
        }

        try (var s = Files.walk(codeDirectory, 3)) {
            if (s.anyMatch(p -> p.toString().endsWith(".java"))) return "java";
        } catch (IOException ignored) {}
        try (var s = Files.walk(codeDirectory, 3)) {
            if (s.anyMatch(p -> p.toString().endsWith(".js")
                    || p.toString().endsWith(".ts")
                    || p.toString().endsWith(".jsx")
                    || p.toString().endsWith(".tsx"))) return "javascript";
        } catch (IOException ignored) {}
        try (var s = Files.walk(codeDirectory, 3)) {
            if (s.anyMatch(p -> p.toString().endsWith(".py"))) return "python";
        } catch (IOException ignored) {}

        log.warn("[{}] Could not detect language – defaulting to 'java'", TOOL_NAME);
        return "java";
    }

    private CompletableFuture<String> drainAsync(Process process) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return new String(process.getInputStream().readAllBytes());
            } catch (IOException e) {
                return "";
            }
        });
    }

    private void cleanupDirectory(Path dir) {
        if (dir == null || !Files.exists(dir)) return;
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(java.io.File::delete);
        } catch (IOException e) {
            log.warn("[{}] Failed to delete temp DB directory: {}", TOOL_NAME, dir);
        }
    }

    private List<String> getOsCommand(String baseCommand) {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            return List.of("cmd.exe", "/c", baseCommand);
        }
        return List.of(baseCommand);
    }
}