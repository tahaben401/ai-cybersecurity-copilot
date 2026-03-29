package com.example.aicybersecuritycopilot.project.model;


import com.example.aicybersecuritycopilot.user.entity.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "projects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String repoUrl;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

//    @OneToMany(mappedBy = "project", cascade = CascadeType.ALL, orphanRemoval = true)
//    @Builder.Default
//    private List<Scan> scans = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
