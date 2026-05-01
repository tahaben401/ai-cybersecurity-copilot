package com.example.aicybersecuritycopilot.scan.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

@Service
@Slf4j
public class RepoCloner {


    private static final String TEMP_CLONE_DIR = System.getProperty("user.dir") + File.separator + "mantis-scans";

    /**
     * Clones a repository to a temporary directory for scanning.
     * @param repoUrl The Git URL
     * @param scanId The unique scan ID (used for folder naming to avoid collisions)
     * @return Path to the cloned repository
     */
    public Path cloneRepository(String repoUrl, UUID scanId) throws IOException {
        Path targetDir = Paths.get(TEMP_CLONE_DIR, scanId.toString());
        
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }

        log.info("Cloning repository {} into {}", repoUrl, targetDir.toAbsolutePath());

        try {
            // --depth=1 is crucial to speed up cloning (shallow clone)
            ProcessBuilder pb = new ProcessBuilder(
                    "git", "clone", "--depth=1", repoUrl, targetDir.toString()
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                log.error("Git clone failed with exit code {}", exitCode);
                throw new IOException("Failed to clone repository. Exit code: " + exitCode);
            }
            
            log.info("Successfully cloned repository for scan {}", scanId);
            return targetDir;
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Git clone process was interrupted", e);
        }
    }


    public void cleanupRepository(UUID scanId) {
        Path targetDir = Paths.get(TEMP_CLONE_DIR, scanId.toString());
        try {
            if (Files.exists(targetDir)) {
                // Windows fix: git sets .git/objects files as read-only,
                // so we must make them writable before deletion
                Files.walk(targetDir)
                        .forEach(path -> path.toFile().setWritable(true));

                FileSystemUtils.deleteRecursively(targetDir);
                log.info("Cleaned up directory {}", targetDir.toAbsolutePath());
            } else {
                log.warn("Cleanup called but directory does not exist: {}", targetDir.toAbsolutePath());
            }
        } catch (IOException e) {
            log.warn("Failed to clean up directory {}: {}", targetDir.toAbsolutePath(), e.getMessage());
        }
    }
}


