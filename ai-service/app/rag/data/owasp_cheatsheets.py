"""
MANTIS AI Service — OWASP Cheatsheets pour Java/Spring Boot.

Résumés des cheatsheets officiels de l'OWASP adaptés à Spring Boot.
Ces documents donnent au Coder Agent des bonnes pratiques de sécurité
détaillées pour chaque catégorie de vulnérabilité.

Source: https://cheatsheetseries.owasp.org/
"""

OWASP_CHEATSHEETS = [
    # ── Authentication ───────────────────────────────────────────
    {
        "topic": "Authentication Security",
        "category": "A07:2021-Identification and Authentication Failures",
        "content": """OWASP Authentication Cheatsheet for Spring Boot:

PASSWORD STORAGE:
- Use BCrypt with minimum 12 rounds or Argon2id for password hashing.
- Spring Security provides BCryptPasswordEncoder and Argon2PasswordEncoder.
- NEVER use MD5, SHA-1, or SHA-256 alone for passwords (too fast, no salt).

AUTHENTICATION MECHANISMS:
- Use Spring Security's built-in AuthenticationManager.
- Implement multi-factor authentication (TOTP) for sensitive operations.
- Use OAuth 2.0 / OpenID Connect for third-party authentication.

SESSION MANAGEMENT:
- Set session timeout: server.servlet.session.timeout=30m.
- Regenerate session ID after login: request.changeSessionId().
- Use secure, httpOnly, sameSite cookies.

BRUTE FORCE PREVENTION:
- Implement rate limiting on /login endpoint (max 5 attempts/minute).
- Add CAPTCHA after 3 failed attempts.
- Implement progressive delays between failed attempts.
- Lock account after 10 failed attempts with admin unlock required.

JWT BEST PRACTICES:
- Use RS256 (asymmetric) over HS256 (symmetric) for JWT signing.
- Set short expiration (15 min access token, 7 days refresh token).
- Store refresh tokens in httpOnly cookies, not localStorage.
- Implement token revocation via blacklist or Redis."""
    },
    # ── Input Validation ─────────────────────────────────────────
    {
        "topic": "Input Validation Security",
        "category": "A03:2021-Injection",
        "content": """OWASP Input Validation Cheatsheet for Spring Boot:

VALIDATION STRATEGY:
- Validate ALL input on the server side (never trust client validation).
- Use allowlists (what IS permitted) not blocklists (what is NOT).
- Validate data type, length, range, and format.

SPRING BOOT IMPLEMENTATION:
- Use @Valid / @Validated on all @RequestBody, @RequestParam, @PathVariable.
- Define constraints with Jakarta Bean Validation: @NotBlank, @Size, @Pattern, @Email.
- Create custom validators with @Constraint for business rules.

EXAMPLE:
    @PostMapping("/users")
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest request) { ... }
    
    public class CreateUserRequest {
        @NotBlank @Size(min=3, max=50) @Pattern(regexp="^[a-zA-Z0-9_]+$")
        private String username;
        @NotBlank @Size(min=8, max=128)
        private String password;
        @Email @NotBlank
        private String email;
    }

SANITIZATION:
- Use OWASP Java Encoder for HTML output: Encode.forHtml(input).
- Use Jsoup.clean() for HTML content with allowlist of permitted tags.
- For SQL: NEVER sanitize — use parameterized queries instead.
- For OS commands: NEVER sanitize — use ProcessBuilder with arg arrays."""
    },
    # ── Cryptography ─────────────────────────────────────────────
    {
        "topic": "Cryptographic Security",
        "category": "A02:2021-Cryptographic Failures",
        "content": """OWASP Cryptography Cheatsheet for Spring Boot:

ENCRYPTION ALGORITHMS:
- Symmetric: Use AES-256-GCM (provides both confidentiality and integrity).
- Asymmetric: Use RSA-2048+ or ECDSA P-256 for digital signatures.
- NEVER use: DES, 3DES, RC4, Blowfish, ECB mode.

HASHING:
- Passwords: BCrypt (12+ rounds) or Argon2id.
- Data integrity: SHA-256 or SHA-3.
- NEVER use: MD5, SHA-1 (collision attacks demonstrated).

KEY MANAGEMENT:
- Never hardcode keys in source code.
- Use environment variables or dedicated key management (HashiCorp Vault).
- Rotate keys periodically (90 days for encryption keys).
- Use separate keys for different purposes (encryption vs signing).

TLS CONFIGURATION:
- Enforce TLS 1.2+ (preferably TLS 1.3).
- In Spring Boot: server.ssl.protocol=TLS, server.ssl.enabled-protocols=TLSv1.3.
- Use HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains.
- Disable weak cipher suites.

RANDOM NUMBER GENERATION:
- Use java.security.SecureRandom for security-sensitive randomness.
- NEVER use java.util.Random for tokens, session IDs, or keys."""
    },
    # ── SQL Injection Prevention ─────────────────────────────────
    {
        "topic": "SQL Injection Prevention",
        "category": "A03:2021-Injection",
        "content": """OWASP SQL Injection Prevention Cheatsheet for Spring Boot:

DEFENSE #1 — PARAMETERIZED QUERIES (Primary):
    // JPA/Hibernate
    @Query("SELECT u FROM User u WHERE u.email = :email")
    User findByEmail(@Param("email") String email);
    
    // JdbcTemplate
    jdbcTemplate.query("SELECT * FROM users WHERE id = ?", mapper, userId);
    
    // Native SQL via EntityManager
    entityManager.createNativeQuery("SELECT * FROM users WHERE name = ?1")
                 .setParameter(1, name);

DEFENSE #2 — SPRING DATA JPA METHOD NAMES (Strongest):
    // Spring Data generates safe queries automatically
    User findByUsername(String username);
    List<Order> findByStatusAndCreatedDateAfter(String status, LocalDate date);

DEFENSE #3 — CRITERIA API (For Dynamic Queries):
    CriteriaBuilder cb = entityManager.getCriteriaBuilder();
    CriteriaQuery<User> query = cb.createQuery(User.class);
    Root<User> root = query.from(User.class);
    query.where(cb.equal(root.get("status"), status));

WHAT NOT TO DO:
    // VULNERABLE — string concatenation
    "SELECT * FROM users WHERE name = '" + name + "'"
    
    // VULNERABLE — String.format
    String.format("SELECT * FROM users WHERE name = '%s'", name)
    
    // VULNERABLE — StringBuilder
    new StringBuilder("SELECT * FROM users WHERE name = '").append(name).append("'")

STORED PROCEDURES:
- Use @Procedure annotation in Spring Data JPA.
- Stored procedures are safe IF they use parameterized internal queries."""
    },
    # ── REST API Security ────────────────────────────────────────
    {
        "topic": "REST API Security",
        "category": "A01:2021-Broken Access Control",
        "content": """OWASP REST API Security Cheatsheet for Spring Boot:

AUTHENTICATION & AUTHORIZATION:
- Use Spring Security with JWT or OAuth 2.0.
- Apply @PreAuthorize on ALL controller methods.
- Implement method-level security for fine-grained access control.

IDOR PREVENTION (Insecure Direct Object Reference):
    // VULNERABLE: trusts user-provided ID
    @GetMapping("/api/orders/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderService.findById(id); // Anyone can access any order!
    }
    
    // SECURE: verifies ownership
    @GetMapping("/api/orders/{id}")
    public Order getOrder(@PathVariable Long id, @AuthenticationPrincipal UserDetails user) {
        Order order = orderService.findById(id);
        if (!order.getUserId().equals(user.getId())) {
            throw new AccessDeniedException("Not your order");
        }
        return order;
    }

RATE LIMITING:
- Implement per-user and per-IP rate limiting.
- Return 429 (Too Many Requests) with Retry-After header.
- Use Bucket4j or Spring Cloud Gateway.

RESPONSE SECURITY HEADERS:
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) {
        http.headers(h -> h
            .contentTypeOptions(Customizer.withDefaults())
            .frameOptions(f -> f.deny())
            .httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000))
        );
    }

INPUT/OUTPUT:
- Validate all input with Bean Validation (@Valid).
- Use @JsonIgnore on sensitive fields (passwords, internal IDs).
- Implement pagination to prevent resource exhaustion.
- Use DTOs — never expose JPA entities directly."""
    },
    # ── Error Handling & Logging ──────────────────────────────────
    {
        "topic": "Secure Error Handling and Logging",
        "category": "A09:2021-Security Logging and Monitoring Failures",
        "content": """OWASP Error Handling and Logging Cheatsheet for Spring Boot:

ERROR HANDLING:
- Return generic error messages to users (never stack traces).
- Use @ControllerAdvice for centralized exception handling.
- Configure: server.error.include-stacktrace=never in production.
- Map exceptions to appropriate HTTP status codes.

    @ControllerAdvice
    public class SecurityExceptionHandler {
        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<?> handleAccessDenied(AccessDeniedException ex) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
            // Never include ex.getMessage() in production responses
        }
    }

LOGGING SECURITY:
- Log authentication events (login, logout, failed attempts).
- Log authorization failures (access denied events).
- Log input validation failures (potential attack indicators).
- NEVER log: passwords, credit cards, tokens, session IDs, PII.

SPRING BOOT ACTUATOR:
- Restrict actuator endpoints in production:
    management.endpoints.web.exposure.include=health,info
    management.endpoint.env.enabled=false
- Require authentication for actuator endpoints.
- Never expose /actuator/env or /actuator/configprops (contains secrets)."""
    },
    # ── File Upload Security ─────────────────────────────────────
    {
        "topic": "Secure File Upload",
        "category": "A04:2021-Insecure Design",
        "content": """OWASP File Upload Security Cheatsheet for Spring Boot:

VALIDATION:
- Check file extension against allowlist (pdf, png, jpg, docx).
- Validate actual MIME type with Apache Tika (don't trust Content-Type header).
- Limit file size: spring.servlet.multipart.max-file-size=10MB.
- Scan files for malware (ClamAV integration).

STORAGE:
- Store files OUTSIDE the web root (not in /static/ or /public/).
- Rename files with UUID to prevent path traversal and name collisions.
- Store metadata (original name, uploader, timestamp) in database.
- Use cloud storage (S3, GCS) with signed URLs for access control.

SERVING FILES:
- Serve files through a controller endpoint (not direct static access).
- Set Content-Disposition: attachment to force download.
- Set X-Content-Type-Options: nosniff to prevent MIME sniffing.
- Validate access permissions before serving.

EXAMPLE:
    String ext = FilenameUtils.getExtension(file.getOriginalFilename());
    if (!ALLOWED_TYPES.contains(ext.toLowerCase())) throw new InvalidFileException();
    String safeName = UUID.randomUUID() + "." + ext;
    Path target = uploadPath.resolve(safeName);
    file.transferTo(target);"""
    },
    # ── Dependency Security ──────────────────────────────────────
    {
        "topic": "Dependency and Supply Chain Security",
        "category": "A06:2021-Vulnerable and Outdated Components",
        "content": """OWASP Dependency Security Cheatsheet for Spring Boot:

VULNERABILITY SCANNING:
- Use OWASP Dependency-Check Maven/Gradle plugin in CI/CD.
- Use Snyk, GitHub Dependabot, or Renovate for automated updates.
- Check dependencies against NVD (National Vulnerability Database).
- Run: mvn org.owasp:dependency-check-maven:check

DEPENDENCY MANAGEMENT:
- Pin all dependency versions in pom.xml (no LATEST or RELEASE).
- Use Spring Boot BOM for consistent versions.
- Review transitive dependencies: mvn dependency:tree
- Remove unused dependencies regularly.

HIGH-RISK LIBRARIES:
- Log4j: Ensure version >= 2.17.1 (Log4Shell fix).
- Jackson: Disable default typing to prevent deserialization attacks.
- Apache Commons Collections: Update to >= 4.1 (gadget chain fix).
- Spring Framework: Keep at latest patch version.

BEST PRACTICES:
- Automate dependency updates in CI/CD pipeline.
- Set up security alerts for critical CVEs.
- Maintain a Software Bill of Materials (SBOM).
- Audit new dependencies before adding them to the project."""
    },
]
