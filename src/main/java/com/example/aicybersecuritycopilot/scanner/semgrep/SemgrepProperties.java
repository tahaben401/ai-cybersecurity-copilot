package com.example.aicybersecuritycopilot.scanner.semgrep;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "scanner.semgrep")
@Getter
@Setter
public class SemgrepProperties {

    private boolean enabled = true;
    private int timeoutSeconds = 300;

    private List<String> rulesets = List.of(
            "auto",
            "p/owasp-top-ten",
            "p/cwe-top-25",
            "p/security-audit",
            "p/secrets"
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

    private long maxFileSizeBytes = 1_000_000;
    private boolean metricsEnabled = false;
    private int maxFindings = 5000;
}
