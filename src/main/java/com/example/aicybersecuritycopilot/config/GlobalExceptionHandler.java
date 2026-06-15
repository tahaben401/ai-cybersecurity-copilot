package com.example.aicybersecuritycopilot.config;

import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Turns uncaught exceptions into structured JSON responses instead of opaque
 * 500s. Crucially, it logs the full stack trace and echoes the exception type
 * and message to the client, so failures (e.g. an AI persistence error) are
 * diagnosable from both the backend console and the browser network tab.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(EntityNotFoundException ex) {
        log.warn("Entity not found: {}", ex.getMessage());
        return build(HttpStatus.NOT_FOUND, ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAny(Exception ex) {
        log.error("Unhandled exception", ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, ex);
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, Exception ex) {
        Map<String, Object> body = Map.of(
                "timestamp", LocalDateTime.now().toString(),
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "exception", ex.getClass().getName(),
                "message", ex.getMessage() != null ? ex.getMessage() : "(no message)"
        );
        return ResponseEntity.status(status).body(body);
    }
}
