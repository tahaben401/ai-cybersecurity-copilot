package com.example.aicybersecuritycopilot.scanner.codeql;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "scanner.codeql")
@Getter
@Setter
public class CodeqlProperties {

    private boolean enabled = true;
    private int timeoutSeconds = 600;


    private List<String> querySuites = List.of(
            "security-extended",
            "security-and-quality"
    );


    private List<String> languages = List.of(
            "java",
            "javascript",
            "python"
    );

    private List<String> excludedDirs = List.of(
            "node_modules",
            "vendor",
            ".git",
            "build",
            "dist",
            "target",
            ".idea",
            "__pycache__"
    );


    private String databaseDir = "";


    private int threads = 0;


    private int ramMb = 4096;

    private boolean metricsEnabled = false;
    private int maxFindings = 5000;
}
