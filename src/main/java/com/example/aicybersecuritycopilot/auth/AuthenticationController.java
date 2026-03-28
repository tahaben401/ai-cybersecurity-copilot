package com.example.aicybersecuritycopilot.auth;

import com.example.aicybersecuritycopilot.auth.dto.AuthenticationRequest;
import com.example.aicybersecuritycopilot.auth.dto.AuthenticationResponse;
import com.example.aicybersecuritycopilot.auth.dto.RegistrationRequest;
import com.example.aicybersecuritycopilot.auth.service.AuthenticationService;
import com.example.aicybersecuritycopilot.config.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService service;
    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody final AuthenticationRequest request) {
        return ResponseEntity.ok(this.service.login(request));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody final RegistrationRequest request) {
        this.service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }





}
