package com.example.aicybersecuritycopilot.ai.client;

import tools.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

/**
 * Thin HTTP client for the Python AI service (FastAPI).
 *
 * <p>The AI service's API key never leaves the backend — the frontend talks only
 * to Spring Boot, which forwards the request with the {@code X-API-Key} header.</p>
 */
@Component
@Slf4j
public class AiServiceClient {

    private final RestClient restClient;

    public AiServiceClient(
            @Value("${ai.service.base-url:http://localhost:8000}") String baseUrl,
            @Value("${ai.service.api-key:}") String apiKey,
            @Value("${ai.service.read-timeout-seconds:300}") long readTimeoutSeconds) {

        // The JDK HttpClient defaults to HTTP/2 and, against a cleartext endpoint,
        // attempts an h2c upgrade. The Python AI service (uvicorn) only speaks
        // HTTP/1.1, so it rejects the upgrade ("Unsupported upgrade request" /
        // "Invalid HTTP request received") and the call fails. Pin to HTTP/1.1.
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(httpClient);
        // A single finding analysis runs a 4-agent LLM pipeline (~35s+), so the
        // read timeout must be generous or slow analyses surface as 500s.
        requestFactory.setReadTimeout(Duration.ofSeconds(readTimeoutSeconds));

        RestClient.Builder builder = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(requestFactory);
        if (apiKey != null && !apiKey.isBlank()) {
            builder.defaultHeader("X-API-Key", apiKey);
        }
        this.restClient = builder.build();
        log.info("AiServiceClient configured for {} (HTTP/1.1, readTimeout={}s)", baseUrl, readTimeoutSeconds);
    }

    /**
     * Calls {@code POST /analyze} on the AI service for a single finding.
     *
     * @param body wrapper of {@code scan_id}, {@code project_id} and {@code finding}
     * @return the raw {@code AIAnalysisResult} document as a {@link JsonNode}
     */
    public JsonNode analyze(Map<String, Object> body) {
        return restClient.post()
                .uri("/analyze")
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .body(JsonNode.class);
    }

    /** Liveness probe used by the health endpoint. */
    public boolean isHealthy() {
        try {
            restClient.get().uri("/health/live").retrieve().toBodilessEntity();
            return true;
        } catch (Exception e) {
            log.warn("AI service health check failed: {}", e.getMessage());
            return false;
        }
    }
}
