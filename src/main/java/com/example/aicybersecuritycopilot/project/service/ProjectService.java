package com.example.aicybersecuritycopilot.project.service;


import com.example.aicybersecuritycopilot.ai.repository.AiAnalysisRepository;
import com.example.aicybersecuritycopilot.finding.repository.FindingRepository;
import com.example.aicybersecuritycopilot.project.dto.CreateProjectRequest;
import com.example.aicybersecuritycopilot.project.model.Project;
import com.example.aicybersecuritycopilot.project.repository.ProjectRepository;
import com.example.aicybersecuritycopilot.scan.entity.Scan;
import com.example.aicybersecuritycopilot.scan.repository.ScanRepository;
import com.example.aicybersecuritycopilot.user.entity.User;
import com.example.aicybersecuritycopilot.user.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ProjectService {
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;
    private final ProjectMapper projectMapper;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final AiAnalysisRepository aiAnalysisRepository;
    public Project createProject(CreateProjectRequest createProjectRequest) {
        String email =(String) SecurityContextHolder.getContext().getAuthentication().getName();
        Project project= projectMapper.toProject(createProjectRequest);
        User user = userRepository.findByEmailIgnoreCase(email).orElseThrow(EntityNotFoundException::new);
        project.setUser(user);
        return projectRepository.save(project);
    }
    public Project findProjectById(UUID id) {
        return projectRepository.findById(id).get();
    }
    public List<Project> findUserProjects(UUID id) {
        return projectRepository.findByUserId(id);
    }
    /**
     * Deletes a project and everything that depends on it, in FK-safe order:
     * findings -> ai analyses -> scans (+ their scanner_runs) -> project.
     * A plain {@code deleteById} would fail with a foreign-key violation as soon
     * as the project has been scanned.
     */
    @Transactional
    public void deleteProjectById(UUID id) {
        Project project = projectRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Project not found: " + id));

        List<Scan> scans = scanRepository.findByProjectIdOrderByStartedAtDesc(id);
        if (!scans.isEmpty()) {
            List<UUID> scanIds = scans.stream().map(Scan::getId).toList();
            findingRepository.deleteByScanIds(scanIds);      // children of scans (FK)
            aiAnalysisRepository.deleteByScanIds(scanIds);   // cached AI results (no FK)
            scanRepository.deleteAll(scans);                 // scans + scan_scanner_runs
            scanRepository.flush();                          // ensure scans are gone before the project
        }
        projectRepository.delete(project);
    }
}
