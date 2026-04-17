package com.example.aicybersecuritycopilot.scanner.trivy;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "scanner.trivy")
@Getter
@Setter
public class TrivyProperties {
    private boolean enabled = true;
    private int timeoutSeconds = 600;
}
