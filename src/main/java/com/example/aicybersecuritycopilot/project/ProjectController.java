package com.example.aicybersecuritycopilot.project;


import com.example.aicybersecuritycopilot.project.dto.CreateProjectRequest;
import com.example.aicybersecuritycopilot.project.model.Project;
import com.example.aicybersecuritycopilot.project.service.ProjectService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/project")
@RequiredArgsConstructor
public class ProjectController {
    private final ProjectService projectService;
    @GetMapping("/{id}")
    public ResponseEntity<Project> findProjectById(@PathVariable UUID id) {
        return ResponseEntity.ok(projectService.findProjectById(id));
    }
    @PostMapping
    public ResponseEntity<Project> saveProject(@RequestBody CreateProjectRequest project) {
        return ResponseEntity.status(HttpStatus.CREATED).body(projectService.createProject(project));
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Object> deleteProject(@PathVariable UUID id) {
        projectService.deleteProjectById(id);
        return ResponseEntity.noContent().build();
    }
}
