"""
MANTIS AI Service — Fix Patterns Java/Spring Boot (Production).

Patterns de correction sécurisée pour les vulnérabilités les plus
courantes dans l'écosystème Java Spring Boot.

Chaque entrée contient :
    - Le code VULNÉRABLE (ce que Semgrep/CodeQL détecte)
    - Le code SÉCURISÉ (ce que le Coder Agent doit générer)
    - L'explication technique (pour le contexte RAG)

Ces patterns sont le "livre de recettes" du Coder Agent.
"""

FIX_PATTERNS_JAVA = [
    # ── SQL Injection (JDBC) ─────────────────────────────────────
    {
        "vulnerability_type": "SQL Injection",
        "language": "java",
        "vulnerable_pattern": (
            'String query = "SELECT * FROM users WHERE username = \'" + username + "\'";\n'
            'Statement stmt = connection.createStatement();\n'
            'ResultSet rs = stmt.executeQuery(query);'
        ),
        "secure_pattern": (
            'String query = "SELECT * FROM users WHERE username = ?";\n'
            'PreparedStatement pstmt = connection.prepareStatement(query);\n'
            'pstmt.setString(1, username);\n'
            'ResultSet rs = pstmt.executeQuery();'
        ),
        "explanation": "Use PreparedStatement with parameterized queries. Parameters are sent separately from the SQL command, preventing semantic injection. This is the OWASP recommended primary defense for SQL injection."
    },
    # ── SQL Injection (JPA Native Query) ─────────────────────────
    {
        "vulnerability_type": "SQL Injection JPA",
        "language": "java",
        "vulnerable_pattern": (
            '@Query(value = "SELECT * FROM users WHERE email = \'" + email + "\'", nativeQuery = true)\n'
            'List<User> findByEmail(String email);'
        ),
        "secure_pattern": (
            '@Query(value = "SELECT * FROM users WHERE email = :email", nativeQuery = true)\n'
            'List<User> findByEmail(@Param("email") String email);'
        ),
        "explanation": "Use named parameters (:email) with @Param annotation in Spring Data JPA native queries. Never use string concatenation in @Query annotations. Spring Data JPA will automatically use PreparedStatement under the hood."
    },
    # ── SQL Injection (JdbcTemplate) ─────────────────────────────
    {
        "vulnerability_type": "SQL Injection JdbcTemplate",
        "language": "java",
        "vulnerable_pattern": (
            'String sql = "SELECT * FROM orders WHERE status = \'" + status + "\'";\n'
            'return jdbcTemplate.query(sql, new OrderRowMapper());'
        ),
        "secure_pattern": (
            'String sql = "SELECT * FROM orders WHERE status = ?";\n'
            'return jdbcTemplate.query(sql, new OrderRowMapper(), status);'
        ),
        "explanation": "Pass user input as varargs parameters to JdbcTemplate.query(). Spring will use PreparedStatement internally. The placeholder ? ensures the input is treated as data, not SQL code."
    },
    # ── XSS (Reflected) ─────────────────────────────────────────
    {
        "vulnerability_type": "Cross-Site Scripting XSS",
        "language": "java",
        "vulnerable_pattern": (
            '@GetMapping("/search")\n'
            'public String search(@RequestParam String q, Model model) {\n'
            '    model.addAttribute("query", q);\n'
            '    return "results"; // Thymeleaf: th:utext="${query}"\n'
            '}'
        ),
        "secure_pattern": (
            '@GetMapping("/search")\n'
            'public String search(@RequestParam String q, Model model) {\n'
            '    String sanitized = HtmlUtils.htmlEscape(q);\n'
            '    model.addAttribute("query", sanitized);\n'
            '    return "results"; // Thymeleaf: th:text="${query}" (auto-escapes)\n'
            '}'
        ),
        "explanation": "Use th:text instead of th:utext in Thymeleaf (th:text auto-escapes HTML). Additionally, use Spring's HtmlUtils.htmlEscape() or OWASP Java Encoder for defense-in-depth. Set Content-Security-Policy headers to prevent inline script execution."
    },
    # ── Path Traversal ───────────────────────────────────────────
    {
        "vulnerability_type": "Path Traversal",
        "language": "java",
        "vulnerable_pattern": (
            '@GetMapping("/download")\n'
            'public ResponseEntity<Resource> download(@RequestParam String filename) {\n'
            '    Path filePath = Paths.get(UPLOAD_DIR, filename);\n'
            '    Resource resource = new FileSystemResource(filePath);\n'
            '    return ResponseEntity.ok().body(resource);\n'
            '}'
        ),
        "secure_pattern": (
            '@GetMapping("/download")\n'
            'public ResponseEntity<Resource> download(@RequestParam String filename) {\n'
            '    Path basePath = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();\n'
            '    Path filePath = basePath.resolve(filename).normalize();\n'
            '    if (!filePath.startsWith(basePath)) {\n'
            '        throw new SecurityException("Path traversal attempt detected");\n'
            '    }\n'
            '    Resource resource = new FileSystemResource(filePath);\n'
            '    if (!resource.exists()) throw new FileNotFoundException();\n'
            '    return ResponseEntity.ok().body(resource);\n'
            '}'
        ),
        "explanation": "Normalize both the base path and the resolved path, then verify the resolved path starts with the base directory. This prevents '../' traversal attacks. Path.normalize() resolves all '..' and '.' sequences, making the startsWith() check reliable."
    },
    # ── Command Injection ────────────────────────────────────────
    {
        "vulnerability_type": "OS Command Injection",
        "language": "java",
        "vulnerable_pattern": (
            'String cmd = "ping -c 1 " + hostname;\n'
            'Runtime.getRuntime().exec(cmd);'
        ),
        "secure_pattern": (
            '// OPTION 1: Use ProcessBuilder with argument array (no shell interpretation)\n'
            'ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", hostname);\n'
            'pb.redirectErrorStream(true);\n'
            'Process process = pb.start();\n'
            '\n'
            '// OPTION 2: Validate input against strict allowlist\n'
            'if (!hostname.matches("^[a-zA-Z0-9.\\\\-]+$")) {\n'
            '    throw new SecurityException("Invalid hostname");\n'
            '}'
        ),
        "explanation": "Never pass a single concatenated string to Runtime.exec() — it gets interpreted by the shell, allowing injection via characters like ; | & $. Use ProcessBuilder with separate arguments: each argument is passed directly to the OS, bypassing shell interpretation entirely."
    },
    # ── XXE (XML External Entity) ────────────────────────────────
    {
        "vulnerability_type": "XXE",
        "language": "java",
        "vulnerable_pattern": (
            'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n'
            'DocumentBuilder builder = factory.newDocumentBuilder();\n'
            'Document doc = builder.parse(inputStream);'
        ),
        "secure_pattern": (
            'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n'
            'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            'factory.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
            'factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n'
            'factory.setXIncludeAware(false);\n'
            'factory.setExpandEntityReferences(false);\n'
            'DocumentBuilder builder = factory.newDocumentBuilder();\n'
            'Document doc = builder.parse(inputStream);'
        ),
        "explanation": "Disable all external entity processing in the XML parser. The most important setting is disabling DOCTYPE declarations entirely. Also disable XInclude and entity reference expansion for complete XXE protection."
    },
    # ── SSRF (Server-Side Request Forgery) ───────────────────────
    {
        "vulnerability_type": "SSRF",
        "language": "java",
        "vulnerable_pattern": (
            '@GetMapping("/fetch")\n'
            'public String fetchUrl(@RequestParam String url) {\n'
            '    RestTemplate restTemplate = new RestTemplate();\n'
            '    return restTemplate.getForObject(url, String.class);\n'
            '}'
        ),
        "secure_pattern": (
            'private static final Set<String> ALLOWED_HOSTS = Set.of("api.github.com", "api.example.com");\n'
            '\n'
            '@GetMapping("/fetch")\n'
            'public String fetchUrl(@RequestParam String url) {\n'
            '    URI uri = URI.create(url);\n'
            '    if (!ALLOWED_HOSTS.contains(uri.getHost())) {\n'
            '        throw new SecurityException("Host not in allowlist");\n'
            '    }\n'
            '    if (isPrivateIP(uri.getHost())) {\n'
            '        throw new SecurityException("Private IP not allowed");\n'
            '    }\n'
            '    RestTemplate restTemplate = new RestTemplate();\n'
            '    return restTemplate.getForObject(uri, String.class);\n'
            '}'
        ),
        "explanation": "Validate URLs against a strict allowlist of permitted hosts. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x) to prevent access to cloud metadata and internal services. Never pass user-controlled URLs directly to HTTP clients."
    },
    # ── Insecure Deserialization ──────────────────────────────────
    {
        "vulnerability_type": "Insecure Deserialization",
        "language": "java",
        "vulnerable_pattern": (
            'ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\n'
            'Object obj = ois.readObject();'
        ),
        "secure_pattern": (
            '// NEVER use ObjectInputStream with untrusted data.\n'
            '// Use JSON serialization with Jackson instead:\n'
            'ObjectMapper mapper = new ObjectMapper();\n'
            'mapper.activateDefaultTyping(null); // DO NOT USE — shown as anti-pattern\n'
            '\n'
            '// CORRECT: Use explicit type mapping\n'
            'MyDTO dto = mapper.readValue(request.getInputStream(), MyDTO.class);\n'
            '\n'
            '// If ObjectInputStream is absolutely required, use serialization filters (JEP 290):\n'
            'ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.myapp.*;!*");\n'
            'ois.setObjectInputFilter(filter);'
        ),
        "explanation": "Java's native serialization (ObjectInputStream) is inherently dangerous with untrusted data — it can lead to Remote Code Execution via gadget chains (Apache Commons Collections, etc.). Use JSON/Jackson with explicit type mapping instead. If ObjectInputStream is required, use JEP 290 serialization filters to allowlist permitted classes."
    },
    # ── Hardcoded Secrets ────────────────────────────────────────
    {
        "vulnerability_type": "Hardcoded Credentials",
        "language": "java",
        "vulnerable_pattern": (
            'private static final String JWT_SECRET = "mySuper$ecretKey123!";\n'
            'private static final String DB_PASSWORD = "admin123";'
        ),
        "secure_pattern": (
            '@Value("${jwt.secret}")\n'
            'private String jwtSecret;\n'
            '\n'
            '@Value("${spring.datasource.password}")\n'
            'private String dbPassword;\n'
            '\n'
            '// In application.properties: reference environment variable\n'
            '// jwt.secret=${JWT_SECRET}\n'
            '// spring.datasource.password=${DB_PASSWORD}'
        ),
        "explanation": "Never hardcode secrets in source code. Use Spring's @Value annotation with externalized configuration. In production, inject secrets via environment variables, Spring Cloud Config Server, or HashiCorp Vault. This ensures secrets are not committed to Git and can be rotated without code changes."
    },
    # ── Weak Password Hashing ────────────────────────────────────
    {
        "vulnerability_type": "Weak Cryptographic Hash",
        "language": "java",
        "vulnerable_pattern": (
            'MessageDigest md = MessageDigest.getInstance("MD5");\n'
            'byte[] hash = md.digest(password.getBytes());\n'
            'String hashedPassword = Base64.getEncoder().encodeToString(hash);'
        ),
        "secure_pattern": (
            '// Use Spring Security\'s BCryptPasswordEncoder\n'
            'PasswordEncoder encoder = new BCryptPasswordEncoder(12); // 12 rounds\n'
            'String hashedPassword = encoder.encode(rawPassword);\n'
            '\n'
            '// For verification:\n'
            'boolean matches = encoder.matches(rawPassword, hashedPassword);'
        ),
        "explanation": "MD5 and SHA-1 are NOT suitable for password hashing — they are too fast (billions of hashes/second). Use BCrypt (adaptive, includes salt automatically, configurable work factor) or Argon2id (memory-hard, resistant to GPU attacks). Spring Security provides BCryptPasswordEncoder out of the box."
    },
    # ── CSRF Disabled Incorrectly ────────────────────────────────
    {
        "vulnerability_type": "CSRF Protection Disabled",
        "language": "java",
        "vulnerable_pattern": (
            '@Bean\n'
            'public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n'
            '    http.csrf().disable(); // DANGEROUS for session-based auth\n'
            '    return http.build();\n'
            '}'
        ),
        "secure_pattern": (
            '@Bean\n'
            'public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {\n'
            '    http\n'
            '        .csrf(csrf -> csrf\n'
            '            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())\n'
            '        );\n'
            '    // For stateless JWT APIs only: csrf can be disabled\n'
            '    // http.csrf(csrf -> csrf.disable());\n'
            '    return http.build();\n'
            '}'
        ),
        "explanation": "Disabling CSRF protection is only safe for stateless REST APIs that use token-based authentication (JWT). For session-based authentication, CSRF protection MUST be enabled. Use CookieCsrfTokenRepository for SPA frontends that need to read the CSRF token from a cookie."
    },
    # ── Unrestricted File Upload ──────────────────────────────────
    {
        "vulnerability_type": "Unrestricted File Upload",
        "language": "java",
        "vulnerable_pattern": (
            '@PostMapping("/upload")\n'
            'public String handleUpload(@RequestParam("file") MultipartFile file) {\n'
            '    String filename = file.getOriginalFilename();\n'
            '    file.transferTo(new File(UPLOAD_DIR + filename));\n'
            '    return "Upload successful";\n'
            '}'
        ),
        "secure_pattern": (
            'private static final Set<String> ALLOWED_EXTENSIONS = Set.of("pdf", "png", "jpg", "docx");\n'
            'private static final long MAX_SIZE = 10 * 1024 * 1024; // 10MB\n'
            '\n'
            '@PostMapping("/upload")\n'
            'public String handleUpload(@RequestParam("file") MultipartFile file) {\n'
            '    if (file.getSize() > MAX_SIZE) throw new FileTooLargeException();\n'
            '    String ext = FilenameUtils.getExtension(file.getOriginalFilename()).toLowerCase();\n'
            '    if (!ALLOWED_EXTENSIONS.contains(ext)) throw new InvalidFileTypeException();\n'
            '    String safeFilename = UUID.randomUUID() + "." + ext;\n'
            '    Path targetPath = Paths.get(UPLOAD_DIR).resolve(safeFilename);\n'
            '    file.transferTo(targetPath);\n'
            '    return "Upload successful";\n'
            '}'
        ),
        "explanation": "Validate file extension against an allowlist (not a blocklist). Replace the original filename with a UUID to prevent path traversal and name collisions. Limit file size. For defense-in-depth, validate the actual file content type using Apache Tika instead of trusting the extension."
    },
    # ── Open Redirect ────────────────────────────────────────────
    {
        "vulnerability_type": "Open Redirect",
        "language": "java",
        "vulnerable_pattern": (
            '@GetMapping("/redirect")\n'
            'public void redirect(@RequestParam String url, HttpServletResponse response) {\n'
            '    response.sendRedirect(url);\n'
            '}'
        ),
        "secure_pattern": (
            'private static final Set<String> ALLOWED_REDIRECT_DOMAINS = Set.of(\n'
            '    "example.com", "app.example.com"\n'
            ');\n'
            '\n'
            '@GetMapping("/redirect")\n'
            'public void redirect(@RequestParam String url, HttpServletResponse response) {\n'
            '    URI uri = URI.create(url);\n'
            '    if (uri.getHost() != null && !ALLOWED_REDIRECT_DOMAINS.contains(uri.getHost())) {\n'
            '        throw new SecurityException("Redirect to unauthorized domain");\n'
            '    }\n'
            '    response.sendRedirect(url);\n'
            '}'
        ),
        "explanation": "Validate redirect URLs against a whitelist of permitted domains. Attackers use open redirects in phishing attacks to make malicious URLs appear legitimate (e.g., https://trusted.com/redirect?url=https://evil.com). Always validate the host component of redirect URLs."
    },
    # ── Missing Rate Limiting ────────────────────────────────────
    {
        "vulnerability_type": "Missing Rate Limiting",
        "language": "java",
        "vulnerable_pattern": (
            '@PostMapping("/login")\n'
            'public ResponseEntity<?> login(@RequestBody LoginRequest request) {\n'
            '    return authService.authenticate(request);\n'
            '}'
        ),
        "secure_pattern": (
            '// Using Bucket4j for rate limiting\n'
            'private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();\n'
            '\n'
            '@PostMapping("/login")\n'
            'public ResponseEntity<?> login(@RequestBody LoginRequest request,\n'
            '                               HttpServletRequest httpRequest) {\n'
            '    String clientIp = httpRequest.getRemoteAddr();\n'
            '    Bucket bucket = buckets.computeIfAbsent(clientIp, k ->\n'
            '        Bucket.builder()\n'
            '            .addLimit(Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(1))))\n'
            '            .build()\n'
            '    );\n'
            '    if (!bucket.tryConsume(1)) {\n'
            '        return ResponseEntity.status(429).body("Too many login attempts");\n'
            '    }\n'
            '    return authService.authenticate(request);\n'
            '}'
        ),
        "explanation": "Login endpoints without rate limiting are vulnerable to brute-force and credential stuffing attacks. Use Bucket4j or Spring Cloud Gateway's built-in rate limiting. Limit to 5 attempts per minute per IP. Consider adding CAPTCHA after 3 failed attempts and implementing account lockout policies."
    },
]
