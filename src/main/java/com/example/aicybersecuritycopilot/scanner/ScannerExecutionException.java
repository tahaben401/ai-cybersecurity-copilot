package com.example.aicybersecuritycopilot.scanner;

public class ScannerExecutionException extends RuntimeException {

    private final String toolName;
    private final int exitCode;

    public ScannerExecutionException(String toolName, String message) {
        super(message);
        this.toolName = toolName;
        this.exitCode = -1;
    }

    public ScannerExecutionException(String toolName, String message, Throwable cause) {
        super(message, cause);
        this.toolName = toolName;
        this.exitCode = -1;
    }

    public ScannerExecutionException(String toolName, int exitCode, String message) {
        super(message);
        this.toolName = toolName;
        this.exitCode = exitCode;
    }

    public String getToolName() {
        return toolName;
    }

    public int getExitCode() {
        return exitCode;
    }
}
