package com.example.aicybersecuritycopilot.scan.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanRequest {
    private UUID projectId;
    private String branch;
}
