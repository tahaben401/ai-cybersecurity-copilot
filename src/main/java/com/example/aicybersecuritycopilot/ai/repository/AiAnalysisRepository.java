package com.example.aicybersecuritycopilot.ai.repository;

import com.example.aicybersecuritycopilot.ai.entity.AiAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AiAnalysisRepository extends JpaRepository<AiAnalysis, UUID> {

    Optional<AiAnalysis> findByFindingId(UUID findingId);

    List<AiAnalysis> findByScanId(UUID scanId);
}
