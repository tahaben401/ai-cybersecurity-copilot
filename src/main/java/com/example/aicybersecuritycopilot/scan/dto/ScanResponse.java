package com.example.aicybersecuritycopilot.scan.dto;

import com.example.aicybersecuritycopilot.scan.entity.ScanStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResponse {
    private UUID scanId;
    private UUID projectId;
    private ScanStatus status;
    private String branch;
    private LocalDateTime startedAt;
}
