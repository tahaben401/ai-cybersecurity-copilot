package com.example.aicybersecuritycopilot.ai.repository;

import com.example.aicybersecuritycopilot.ai.entity.AiAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AiAnalysisRepository extends JpaRepository<AiAnalysis, UUID> {

    Optional<AiAnalysis> findByFindingId(UUID findingId);

    List<AiAnalysis> findByScanId(UUID scanId);

    /** Bulk-delete AI analyses for the given scans (no FK constraint, cleaned up explicitly). */
    @Modifying
    @Query("delete from AiAnalysis a where a.scanId in :scanIds")
    void deleteByScanIds(@Param("scanIds") Collection<UUID> scanIds);
}
