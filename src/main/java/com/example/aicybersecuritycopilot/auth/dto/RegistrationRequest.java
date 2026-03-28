package com.example.aicybersecuritycopilot.auth.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RegistrationRequest {
    String email;
    String password;
    String confirmPassword;
}
