package com.example.aicybersecuritycopilot.project.service;


import com.example.aicybersecuritycopilot.project.dto.CreateProjectRequest;
import com.example.aicybersecuritycopilot.project.model.Project;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ProjectMapper {
    public Project toProject(CreateProjectRequest createProjectRequest) {
        return Project.builder()
                .name(createProjectRequest.getProjectName())
                .repoUrl(createProjectRequest.getRepoUrl())
                .build();

    }
}
