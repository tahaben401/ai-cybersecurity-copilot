package com.example.aicybersecuritycopilot.scan.repository;

import com.example.aicybersecuritycopilot.scan.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {
}
