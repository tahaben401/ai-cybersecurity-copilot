package com.example.aicybersecuritycopilot.broker.dto;

import com.example.aicybersecuritycopilot.scanner.sarif.FindingDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanResultMessage {
    private UUID scanId;
    private UUID projectId;
    private String branch;
    private List<FindingDTO> findings;
}
