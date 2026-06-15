package com.example.aicybersecuritycopilot.scanner.codeql;

import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import com.example.aicybersecuritycopilot.scanner.SecurityScanner;

import jakarta.annotation.PostConstruct;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
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

        List<String> languages = resolveLanguages(codeDirectory);
        if (languages.isEmpty()) {
            log.warn("[{}] No supported language detected – nothing to scan", TOOL_NAME);
            return ScannerResult.builder()
                    .toolName(TOOL_NAME).success(true)
                    .sarifContent("{}").findingsCount(0).executionTimeMs(0)
                    .build();
        }

        log.info("[{}] Starting scan on {} – languages: {}", TOOL_NAME, codeDirectory, languages);
        long start = System.currentTimeMillis();

        // Analyse each detected language in its own database, then merge the SARIF
        // documents (the parser already supports multiple runs per report).
        List<String> sarifReports = new ArrayList<>();
        int totalFindings = 0;

        for (String language : languages) {
            String uniqueId = UUID.randomUUID().toString().substring(0, 8);
            Path base = properties.getDatabaseDir() != null && !properties.getDatabaseDir().isBlank()
                    ? Paths.get(properties.getDatabaseDir())
                    : Path.of(System.getProperty("java.io.tmpdir"));

            Path dbDir;
            Path sarifOutput;
            try {
                dbDir       = Files.createDirectories(base.resolve("mantis-codeql-db-" + language + "-" + uniqueId));
                sarifOutput = Files.createTempFile("mantis-codeql-" + language + "-", ".sarif");
            } catch (IOException e) {
                throw new ScannerExecutionException(TOOL_NAME, "Cannot create temp files", e);
            }

            try {
                buildDatabase(codeDirectory, dbDir, language);
                int exitCode = analyzeDatabase(dbDir, sarifOutput, language);
                if (exitCode != 0) {
                    log.warn("[{}] '{}' analysis exited with code {} – skipping language", TOOL_NAME, language, exitCode);
                    continue;
                }
                if (Files.exists(sarifOutput) && Files.size(sarifOutput) > 0) {
                    String sarif = Files.readString(sarifOutput);
                    sarifReports.add(sarif);
                    totalFindings += countResults(sarif);
                }
            } catch (ScannerExecutionException e) {
                log.warn("[{}] '{}' failed: {} – continuing with other languages", TOOL_NAME, language, e.getMessage());
            } catch (Exception e) {
                log.error("[{}] '{}' unexpected error", TOOL_NAME, language, e);
            } finally {
                try { Files.deleteIfExists(sarifOutput); } catch (IOException ignored) {}
                cleanupDirectory(dbDir);
            }
        }

        long elapsed = System.currentTimeMillis() - start;

        if (sarifReports.isEmpty()) {
            return ScannerResult.builder()
                    .toolName(TOOL_NAME).executionTimeMs(elapsed).success(false)
                    .errorMessage("CodeQL produced no results for languages: " + languages)
                    .build();
        }

        String merged = mergeSarifReports(sarifReports);
        log.info("[{}] Scan complete in {}ms – {} finding(s) across {} language(s)",
                TOOL_NAME, elapsed, totalFindings, sarifReports.size());

        return ScannerResult.builder()
                .toolName(TOOL_NAME).exitCode(0)
                .sarifContent(merged).executionTimeMs(elapsed)
                .success(true).findingsCount(totalFindings)
                .build();
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
                "--overwrite"
        ));
        // build-mode=none lets compiled languages (Java) be analysed without a build.
        // Interpreted languages (JS/Python) are extracted directly and reject this flag.
        if (needsBuildMode(language)) cmd.add("--build-mode=none");
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

    /**
     * Returns every configured language that actually has source files present.
     * Configuring a single language pins to it; "auto"/empty falls back to scanning
     * for java, javascript and python. CodeQL needs one database per language.
     */
    private List<String> resolveLanguages(Path codeDirectory) {
        List<String> configured = properties.getLanguages();
        List<String> candidates;
        if (configured == null || configured.isEmpty()
                || configured.stream().anyMatch(l -> "auto".equalsIgnoreCase(l))) {
            candidates = List.of("java", "javascript", "python");
        } else {
            candidates = configured.stream().map(String::trim).filter(s -> !s.isBlank()).toList();
        }

        List<String> present = new ArrayList<>();
        for (String lang : candidates) {
            if (hasFilesForLanguage(codeDirectory, lang)) present.add(lang);
        }
        return present;
    }

    private boolean hasFilesForLanguage(Path dir, String language) {
        List<String> exts = switch (language.toLowerCase()) {
            case "java" -> List.of(".java");
            case "javascript", "typescript" -> List.of(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs");
            case "python" -> List.of(".py");
            default -> List.of();
        };
        if (exts.isEmpty()) return false;
        try (var s = Files.walk(dir)) {
            return s.anyMatch(p -> {
                String n = p.toString().toLowerCase();
                return exts.stream().anyMatch(n::endsWith);
            });
        } catch (IOException e) {
            return false;
        }
    }

    /** Compiled languages need a build mode; interpreted ones are extracted directly. */
    private boolean needsBuildMode(String language) {
        return switch (language.toLowerCase()) {
            case "java", "csharp", "cpp", "go", "kotlin", "swift" -> true;
            default -> false;
        };
    }

    /** Counts results across all runs of a single SARIF report. */
    private int countResults(String sarif) {
        int count = 0;
        try (JsonReader reader = Json.createReader(new StringReader(sarif))) {
            JsonArray runs = reader.readObject().getJsonArray("runs");
            if (runs != null) {
                for (int i = 0; i < runs.size(); i++) {
                    JsonArray results = runs.getJsonObject(i).getJsonArray("results");
                    if (results != null) count += results.size();
                }
            }
        } catch (Exception e) {
            log.warn("[{}] Could not count SARIF results", TOOL_NAME);
        }
        return count;
    }

    /** Merges per-language SARIF documents into one report (concatenates their runs). */
    private String mergeSarifReports(List<String> reports) {
        if (reports.size() == 1) return reports.get(0);
        JsonArrayBuilder runs = Json.createArrayBuilder();
        for (String report : reports) {
            try (JsonReader reader = Json.createReader(new StringReader(report))) {
                JsonArray rs = reader.readObject().getJsonArray("runs");
                if (rs != null) rs.forEach(runs::add);
            } catch (Exception e) {
                log.warn("[{}] Skipping an unparseable SARIF report during merge: {}", TOOL_NAME, e.getMessage());
            }
        }
        return Json.createObjectBuilder()
                .add("version", "2.1.0")
                .add("$schema", "https://json.schemastore.org/sarif-2.1.0.json")
                .add("runs", runs)
                .build()
                .toString();
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