package com.example.aicybersecuritycopilot.scan.repository;

import com.example.aicybersecuritycopilot.scan.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    List<Scan> findByProjectIdOrderByStartedAtDesc(UUID projectId);

    List<Scan> findByProject_User_IdOrderByStartedAtDesc(UUID userId);
}
