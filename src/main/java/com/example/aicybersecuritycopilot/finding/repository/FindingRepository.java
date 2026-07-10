package com.example.aicybersecuritycopilot.finding.repository;


import com.example.aicybersecuritycopilot.finding.model.Finding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScanIdOrderBySeverityAsc(UUID scanId);

    long countByScanId(UUID scanId);

    /** Bulk-delete all findings belonging to the given scans (used when deleting a project). */
    @Modifying
    @Query("delete from Finding f where f.scan.id in :scanIds")
    void deleteByScanIds(@Param("scanIds") Collection<UUID> scanIds);

    /**
     * Severity histogram for a single scan: rows of [severity, count].
     */
    @Query("select f.severity, count(f) from Finding f where f.scan.id = :scanId group by f.severity")
    List<Object[]> countSeverityByScan(@Param("scanId") UUID scanId);

    /**
     * Severity histogram across many scans in one query: rows of [scanId, severity, count].
     * Used to enrich scan lists without an N+1 explosion.
     */
    @Query("select f.scan.id, f.severity, count(f) from Finding f " +
            "where f.scan.id in :scanIds group by f.scan.id, f.severity")
    List<Object[]> countSeverityByScans(@Param("scanIds") Collection<UUID> scanIds);
}
