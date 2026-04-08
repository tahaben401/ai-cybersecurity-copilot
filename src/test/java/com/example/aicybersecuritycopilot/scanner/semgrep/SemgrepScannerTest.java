package com.example.aicybersecuritycopilot.scanner.semgrep;

import com.example.aicybersecuritycopilot.scanner.ScannerExecutionException;
import com.example.aicybersecuritycopilot.scanner.ScannerResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link SemgrepScanner}.
 * Verifies validation and availability logic without actually
 * running the Semgrep CLI (which is done in integration tests).
 */
@ExtendWith(MockitoExtension.class)
class SemgrepScannerTest {

    @Mock
    private SemgrepProperties properties;

    @InjectMocks
    private SemgrepScanner scanner;

    private Path tempCodeDir;

    @BeforeEach
    void setUp() throws Exception {
        tempCodeDir = Files.createTempDirectory("mantis-test-repo-");
    }

    @Test
    @DisplayName("Should throw exception if scanner is disabled in config")
    void shouldThrowIfDisabled() {
        // Arrange
        when(properties.isEnabled()).thenReturn(false);

        // Act & Assert
        ScannerExecutionException exception = assertThrows(ScannerExecutionException.class, () ->
            scanner.scan(tempCodeDir)
        );
        assertTrue(exception.getMessage().contains("disabled"));
    }

    @Test
    @DisplayName("Should throw exception if code directory is null")
    void shouldThrowIfDirNull() {
        // Arrange
        when(properties.isEnabled()).thenReturn(true);

        // Act & Assert
        assertThrows(ScannerExecutionException.class, () ->
            scanner.scan(null)
        );
    }

    @Test
    @DisplayName("Tool name should be Semgrep")
    void toolNameShouldBeSemgrep() {
        assertEquals("Semgrep", scanner.getToolName());
    }

    // Note: Testing the actual scan() execution requires mocking ProcessBuilder,
    // which is heavily OS-dependent and deeply nested. Standard practice is to
    // test the business logic (validation) here and rely on integration tests
    // for the CLI invocation.
}
