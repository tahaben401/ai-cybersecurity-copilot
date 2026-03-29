package com.example.aicybersecuritycopilot.project.service;


import com.example.aicybersecuritycopilot.project.dto.CreateProjectRequest;
import com.example.aicybersecuritycopilot.project.model.Project;
import com.example.aicybersecuritycopilot.project.repository.ProjectRepository;
import com.example.aicybersecuritycopilot.user.entity.User;
import com.example.aicybersecuritycopilot.user.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ProjectService {
    private final ProjectRepository projectRepository;
    private final UserRepository userRepository;
    private final ProjectMapper projectMapper;
    public Project createProject(CreateProjectRequest createProjectRequest) {
        String email =(String) SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("email: "+email);
        Project project= projectMapper.toProject(createProjectRequest);
        User user = userRepository.findByEmailIgnoreCase(email).orElseThrow(EntityNotFoundException::new);
        project.setUser(user);
        return projectRepository.save(project);
    }
    public Project findProjectById(UUID id) {
        return projectRepository.findById(id).get();
    }
    public void deleteProjectById(UUID id) {
        projectRepository.deleteById(id);
    }
}
