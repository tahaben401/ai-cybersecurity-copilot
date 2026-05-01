package com.example.aicybersecuritycopilot.finding.model;

import com.example.aicybersecuritycopilot.scan.entity.Scan;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(name = "findings")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    private String toolName;
    private String ruleId;
    private String severity;      // CRITICAL, HIGH, MEDIUM, LOW, INFO
    private String filePath;
    private int startLine;
    private int endLine;

    @Column(columnDefinition = "TEXT")
    private String message;

    @Column(columnDefinition = "TEXT")
    private String snippet;

    @Column(columnDefinition = "TEXT")
    private String ruleDescription;

    @Column(columnDefinition = "TEXT")
    private String suggestedFix;

    private String cweId;
    private String owaspCategory;
    private String fingerprint;
}
