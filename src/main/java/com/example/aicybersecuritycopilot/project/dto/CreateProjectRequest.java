package com.example.aicybersecuritycopilot.project.dto;


import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CreateProjectRequest {
    private String projectName;
    private String repoUrl;

}
