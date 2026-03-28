package com.example.aicybersecuritycopilot.user.service;

import com.example.aicybersecuritycopilot.auth.dto.RegistrationRequest;
import com.example.aicybersecuritycopilot.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserMapper {
    private final PasswordEncoder passwordEncoder;

    public User toUser(final RegistrationRequest request) {
        return User.builder()
                .email(request.getEmail())
                .password(this.passwordEncoder.encode(request.getPassword()))
                .role(User.Role.USER)
                .build();
    }
}
