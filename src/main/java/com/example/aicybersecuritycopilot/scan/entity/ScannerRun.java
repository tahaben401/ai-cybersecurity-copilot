package com.example.aicybersecuritycopilot.scan.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Per-scanner outcome for a single scan (Semgrep / CodeQL / Trivy).
 *
 * <p>Persisted as an embedded collection on {@link Scan} so the UI can show
 * <em>why</em> a scanner produced no findings (e.g. "CodeQL — failed/timeout")
 * instead of silently dropping the failure.</p>
 */
@Embeddable
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScannerRun {

    @Column(name = "tool_name")
    private String tool;

    private boolean success;

    @Column(name = "findings_count")
    private int findings;

    @Column(name = "duration_ms")
    private long durationMs;

    /** Failure reason when {@code success} is false; null otherwise. */
    @Column(length = 600)
    private String error;
}
