package com.example.aicybersecuritycopilot.ai.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Persisted result of an AI analysis for a single finding.
 *
 * <p>The full {@code AIAnalysisResult} JSON returned by the Python AI service is
 * stored verbatim in {@link #resultJson}, while a few columns are promoted for
 * indexing/filtering. This keeps the Java side decoupled from the evolving AI
 * schema — we pass the document straight through to the frontend.</p>
 */
@Entity
@Table(name = "ai_analyses")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AiAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private UUID findingId;

    @Column(nullable = false)
    private UUID scanId;

    private UUID projectId;

    /** APPROVED / REJECTED / GENERATED / FAILED — mirror of overall_status. */
    private String status;

    // NOTE: no @Lob here. On PostgreSQL, @Lob on a String binds the value as a
    // Large Object (oid), which clashes with this TEXT column ("column is of type
    // text but expression is of type oid") and fails the save with a 500.
    // A plain String mapped to TEXT stores the full AI JSON document correctly.
    @Column(columnDefinition = "TEXT", nullable = false)
    private String resultJson;

    @Column(nullable = false)
    private LocalDateTime processedAt;

    @PrePersist
    @PreUpdate
    void touch() {
        this.processedAt = LocalDateTime.now();
    }
}
