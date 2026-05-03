package com.example.aicybersecuritycopilot.finding.repository;


import com.example.aicybersecuritycopilot.finding.model.Finding;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;
public interface FindingRepository extends JpaRepository<Finding, UUID> {
}
