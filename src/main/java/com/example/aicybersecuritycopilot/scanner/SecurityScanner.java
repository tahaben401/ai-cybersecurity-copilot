package com.example.aicybersecuritycopilot.scanner;

import java.nio.file.Path;

public interface SecurityScanner {
    ScannerResult scan(Path codeDirectory) throws ScannerExecutionException;
    String getToolName();
    boolean isAvailable();
}
/*hadi seulement une contrat pour dire que toutes outile de securite khasah une methode scan() */