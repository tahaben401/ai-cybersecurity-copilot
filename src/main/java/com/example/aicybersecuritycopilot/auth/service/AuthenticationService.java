package com.example.aicybersecuritycopilot.auth.service;

import com.example.aicybersecuritycopilot.auth.dto.AuthenticationRequest;
import com.example.aicybersecuritycopilot.auth.dto.AuthenticationResponse;
import com.example.aicybersecuritycopilot.auth.dto.RegistrationRequest;
import com.example.aicybersecuritycopilot.config.security.JwtService;
import com.example.aicybersecuritycopilot.user.entity.User;
import com.example.aicybersecuritycopilot.user.repository.UserRepository;
import com.example.aicybersecuritycopilot.user.service.UserMapper;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public AuthenticationResponse login(final AuthenticationRequest request) {
        final Authentication auth = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        final User user = (User) auth.getPrincipal();
        final String accessToken = this.jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .build();

    }


    @Transactional
    public void register(final RegistrationRequest request) {

        final User user = this.userMapper.toUser(request);
        this.userRepository.save(user);

    }

    public void logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            SecurityContextHolder.clearContext();
        }
    }


}
