"""
MANTIS AI Service — CWE Top 25 Most Dangerous Software Weaknesses.

Source: MITRE CWE Top 25 (2024)
https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html

Ces 25 faiblesses couvrent ~95% des vulnérabilités détectées par
les scanners de sécurité modernes (Semgrep, CodeQL, SonarQube).
"""

CWE_TOP_25 = [
    # ── #1 — Out-of-bounds Write ─────────────────────────────────
    {
        "cwe_id": "CWE-787",
        "description": "Out-of-bounds Write. The product writes data past the end, or before the beginning, of the intended buffer. This can result in corruption of data, a crash, or code execution. In Java, this is less common due to automatic bounds checking, but can occur in native code (JNI) or unsafe buffer operations.",
        "consequences": "Memory corruption leading to crashes, arbitrary code execution, or denial of service. In Java context, this manifests as ArrayIndexOutOfBoundsException or buffer overflow in native methods.",
        "mitigations": "Use safe collection classes. Validate array indices before access. Avoid direct memory manipulation. In JNI code, use bounds-checked functions."
    },
    # ── #2 — Cross-site Scripting (XSS) ─────────────────────────
    {
        "cwe_id": "CWE-79",
        "description": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting). The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users. In Spring Boot, this commonly occurs in Thymeleaf templates, REST API responses rendered in browser, or when using th:utext instead of th:text.",
        "consequences": "Attackers can execute malicious scripts in victim browsers, leading to session hijacking via stolen cookies, account takeover, defacement, keylogging, or redirection to phishing sites. Stored XSS is particularly dangerous as it persists and affects all users viewing the affected content.",
        "mitigations": "Use context-aware output encoding (OWASP Java Encoder). In Thymeleaf, use th:text (auto-escapes) instead of th:utext. Set Content-Security-Policy headers. Use HTTPOnly and Secure flags on cookies. Implement input validation with allowlists."
    },
    # ── #3 — SQL Injection ───────────────────────────────────────
    {
        "cwe_id": "CWE-89",
        "description": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection). The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command. In Spring Boot, this occurs with raw JDBC, native queries in JPA (@Query with string concatenation), or custom Repository implementations.",
        "consequences": "Full database compromise: read, modify, or delete all data. Bypass authentication and authorization. Execute administrative operations on the database. In severe cases, read files from the server filesystem or execute OS commands via xp_cmdshell (SQL Server) or COPY (PostgreSQL).",
        "mitigations": "Use JPA/Hibernate with parameterized JPQL queries. Use Spring Data JPA method naming conventions (findByUsername). For native SQL, use PreparedStatement with bind parameters (?). Never concatenate user input into SQL strings. Use the Criteria API for dynamic queries."
    },
    # ── #4 — Use After Free ──────────────────────────────────────
    {
        "cwe_id": "CWE-416",
        "description": "Use After Free. Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code. In Java, the garbage collector prevents most use-after-free issues, but they can occur in JNI native code, or logically when using closed resources (streams, connections, database cursors).",
        "consequences": "Program crashes, data corruption, or arbitrary code execution in native code. In Java, manifests as IllegalStateException on closed resources or NullPointerException on dereferenced objects.",
        "mitigations": "Use try-with-resources for auto-closeable resources. Avoid manual memory management in JNI. Use WeakReferences for cache patterns. Validate resource state before operations."
    },
    # ── #5 — OS Command Injection ────────────────────────────────
    {
        "cwe_id": "CWE-78",
        "description": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection). The application constructs all or part of an OS command using externally-influenced input without properly neutralizing special elements that could modify the intended command. In Java/Spring Boot, this occurs when using Runtime.exec(), ProcessBuilder, or Apache Commons Exec with unsanitized user input.",
        "consequences": "Complete server compromise. Attackers can execute arbitrary system commands with the privileges of the Java process. This can lead to data exfiltration, malware installation, lateral movement, or full infrastructure takeover.",
        "mitigations": "Avoid OS commands entirely — use Java libraries instead (e.g., Java NIO for file operations). If commands are unavoidable, use ProcessBuilder with argument arrays (not shell strings). Never pass user input to Runtime.exec(). Implement strict input allowlists."
    },
    # ── #6 — Improper Input Validation ───────────────────────────
    {
        "cwe_id": "CWE-20",
        "description": "Improper Input Validation. The product receives input but does not validate or incorrectly validates that the input has the properties required to process the data safely. In Spring Boot, this means missing @Valid/@Validated annotations, lack of Bean Validation constraints, or insufficient custom validators on REST API endpoints.",
        "consequences": "Enables downstream attacks (SQLi, XSS, command injection). Data corruption from malformed input. Application crashes from unexpected data types or sizes. Business logic bypass.",
        "mitigations": "Use Bean Validation (JSR 380) with @Valid on all @RequestBody and @RequestParam. Define custom validators for business rules. Validate on both client and server side. Use Spring's @Validated at class level for method-level validation."
    },
    # ── #7 — Out-of-bounds Read ──────────────────────────────────
    {
        "cwe_id": "CWE-125",
        "description": "Out-of-bounds Read. The product reads data past the end or before the beginning of the intended buffer. In Java, ArrayIndexOutOfBoundsException prevents memory corruption, but logical out-of-bounds reads can leak sensitive data from collections or arrays.",
        "consequences": "Information disclosure of sensitive data. Application crashes. In native code, can lead to reading adjacent memory containing secrets, keys, or other users' data (similar to Heartbleed).",
        "mitigations": "Always validate indices before array/list access. Use Collections API instead of raw arrays. In JNI, use bounds-checked buffer access functions."
    },
    # ── #8 — Path Traversal ──────────────────────────────────────
    {
        "cwe_id": "CWE-22",
        "description": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal). The software uses external input to construct a pathname intended to identify a file within a restricted directory, but does not properly neutralize sequences like '../' that can resolve to a location outside. In Spring Boot, this occurs in file upload/download endpoints, static resource serving, or template resolution.",
        "consequences": "Read arbitrary files from the server (configuration files, /etc/passwd, application.properties with database credentials, private keys). Write malicious files (web shells, overwrite configurations). In severe cases, achieve remote code execution.",
        "mitigations": "Use Path.normalize() and verify the canonical path starts with the base directory. Use Spring's ResourceLoader instead of direct file access. Reject filenames containing '..' or absolute paths. Use UUID-based filenames for uploads."
    },
    # ── #9 — CSRF ────────────────────────────────────────────────
    {
        "cwe_id": "CWE-352",
        "description": "Cross-Site Request Forgery (CSRF). The web application does not sufficiently verify that a request was intentionally submitted by the authenticated user. In Spring Boot, CSRF protection is enabled by default in Spring Security, but developers sometimes disable it incorrectly with http.csrf().disable() for REST APIs without understanding the implications.",
        "consequences": "Attackers can trick authenticated users into performing unintended actions: changing passwords, transferring funds, modifying account settings, or performing administrative operations without the user's knowledge.",
        "mitigations": "Keep Spring Security CSRF protection enabled for session-based authentication. For stateless REST APIs using JWT tokens, CSRF protection can be safely disabled (the token itself prevents CSRF). Use SameSite cookie attribute. Verify Origin and Referer headers."
    },
    # ── #10 — Unrestricted Upload ────────────────────────────────
    {
        "cwe_id": "CWE-434",
        "description": "Unrestricted Upload of File with Dangerous Type. The product allows the upload of files without checking their type, size, or content, allowing attackers to upload malicious files. In Spring Boot, this occurs in @PostMapping endpoints handling MultipartFile without proper validation.",
        "consequences": "Remote code execution via uploaded web shells (JSP, PHP). Server-side denial of service via large file uploads. Stored XSS via HTML/SVG files. Malware distribution to other users who download the files.",
        "mitigations": "Validate file extension against an allowlist. Check MIME type using Apache Tika (don't trust Content-Type header). Limit file size with spring.servlet.multipart.max-file-size. Store files outside the web root. Rename uploaded files with UUID. Scan files with antivirus."
    },
    # ── #11 — Missing Authorization ──────────────────────────────
    {
        "cwe_id": "CWE-862",
        "description": "Missing Authorization. The product does not perform authorization checks when accessing resources or performing actions. In Spring Boot, this means missing @PreAuthorize, @Secured, or @RolesAllowed annotations on controller methods, or incorrect SecurityFilterChain configuration that leaves endpoints unprotected.",
        "consequences": "Horizontal privilege escalation (accessing other users' data). Vertical privilege escalation (performing admin actions as a regular user). Complete bypass of access control leading to unauthorized data access or modification.",
        "mitigations": "Use @PreAuthorize with SpEL expressions for method-level security. Configure SecurityFilterChain with .authorizeHttpRequests() to protect all endpoints by default (deny-by-default). Use @AuthenticationPrincipal to verify resource ownership. Implement integration tests for authorization."
    },
    # ── #12 — NULL Pointer Dereference ───────────────────────────
    {
        "cwe_id": "CWE-476",
        "description": "NULL Pointer Dereference. A NULL pointer dereference occurs when the application attempts to use a pointer/reference that it expects to be valid but is NULL. In Java, this manifests as NullPointerException. While not a direct security vulnerability, it can cause denial of service and may indicate deeper logic flaws.",
        "consequences": "Application crashes (denial of service). Unexpected behavior that may bypass security checks. In error handlers, may leak stack traces with sensitive information.",
        "mitigations": "Use Optional<T> instead of null returns. Apply @NonNull/@Nullable annotations. Use Objects.requireNonNull() for preconditions. Enable NullAway or Checker Framework static analysis."
    },
    # ── #13 — Improper Authentication ────────────────────────────
    {
        "cwe_id": "CWE-287",
        "description": "Improper Authentication. The product does not properly verify the identity of a user before granting access. In Spring Boot, this includes weak password policies, missing multi-factor authentication, insecure 'remember me' implementations, or custom authentication filters that bypass Spring Security's built-in mechanisms.",
        "consequences": "Account takeover. Unauthorized access to protected resources. Identity spoofing. Complete bypass of security controls.",
        "mitigations": "Use Spring Security's built-in authentication providers. Implement BCrypt or Argon2 password hashing. Add rate limiting to login endpoints. Implement account lockout after failed attempts. Use Spring Security's remember-me with persistent tokens."
    },
    # ── #14 — Integer Overflow ───────────────────────────────────
    {
        "cwe_id": "CWE-190",
        "description": "Integer Overflow or Wraparound. An integer overflow occurs when an arithmetic operation results in a value that exceeds the maximum size of the integer type. In Java, integer overflow wraps around silently (no exception), which can lead to incorrect calculations for array sizes, loop bounds, or financial calculations.",
        "consequences": "Buffer allocation errors (allocating smaller buffer than needed). Infinite loops. Incorrect financial calculations. Security check bypass when size/length comparisons wrap around.",
        "mitigations": "Use Math.addExact(), Math.multiplyExact() which throw ArithmeticException on overflow. Use long or BigInteger for large calculations. Validate input ranges before arithmetic. Use BigDecimal for financial calculations."
    },
    # ── #15 — Deserialization of Untrusted Data ──────────────────
    {
        "cwe_id": "CWE-502",
        "description": "Deserialization of Untrusted Data. The application deserializes data from untrusted sources without proper validation, allowing attackers to manipulate serialized objects to execute arbitrary code. In Java/Spring Boot, this is extremely dangerous due to Java's native serialization (ObjectInputStream), Jackson polymorphic deserialization, or XML/YAML deserialization.",
        "consequences": "Remote code execution (RCE) — the most severe impact. Attackers can execute arbitrary OS commands on the server. This is the vulnerability class behind Log4Shell (CVE-2021-44228) and numerous Apache Commons Collections exploits.",
        "mitigations": "Never use Java native serialization (ObjectInputStream) with untrusted data. Configure Jackson to disable default typing (@JsonTypeInfo). Use allowlists for polymorphic deserialization. Keep libraries updated (Jackson, XStream, SnakeYAML). Use serialization filters (JEP 290)."
    },
    # ── #16 — Improper Access Control ────────────────────────────
    {
        "cwe_id": "CWE-284",
        "description": "Improper Access Control. The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor. This is the parent CWE of many authorization issues. In Spring Boot, this includes misconfigured SecurityFilterChain, exposed actuator endpoints, or missing method-level security annotations.",
        "consequences": "Unauthorized data access. Privilege escalation. Exposure of administrative functions. Access to health/metrics/env actuator endpoints revealing sensitive configuration.",
        "mitigations": "Apply defense-in-depth with both URL-based (SecurityFilterChain) and method-level (@PreAuthorize) security. Restrict Spring Boot Actuator endpoints. Follow least privilege principle. Implement comprehensive authorization tests."
    },
    # ── #17 — Improper Restriction of Operations within Memory ───
    {
        "cwe_id": "CWE-119",
        "description": "Improper Restriction of Operations within the Bounds of a Memory Buffer. The product performs operations on a memory buffer without sufficient boundary checks. In Java, the JVM prevents direct memory corruption, but this can occur in JNI/JNA native code, Unsafe class usage, or direct ByteBuffer operations.",
        "consequences": "Memory corruption in native code. Data leakage from adjacent memory regions. Application crashes or undefined behavior.",
        "mitigations": "Avoid sun.misc.Unsafe. Use bounds-checked ByteBuffer operations. In JNI, validate all array indices and buffer sizes. Use Java's memory-safe abstractions wherever possible."
    },
    # ── #18 — Incorrect Authorization ────────────────────────────
    {
        "cwe_id": "CWE-863",
        "description": "Incorrect Authorization. The product performs authorization checks that do not correctly determine access rights, allowing unauthorized actors to access protected resources. In Spring Boot, this includes IDOR (Insecure Direct Object Reference) vulnerabilities where users can access resources by changing IDs in URLs.",
        "consequences": "Horizontal privilege escalation: User A accesses User B's data by changing /api/users/123 to /api/users/456. Vertical privilege escalation: regular user accesses admin-only resources.",
        "mitigations": "Always verify resource ownership in service layer (not just role). Use @AuthenticationPrincipal to get current user. Implement ABAC (Attribute-Based Access Control) for complex authorization. Never rely solely on client-provided IDs for authorization."
    },
    # ── #19 — Server-Side Request Forgery (SSRF) ────────────────
    {
        "cwe_id": "CWE-918",
        "description": "Server-Side Request Forgery (SSRF). The web server receives a URL or resource identifier from the user and retrieves the resource without validating the destination. In Spring Boot, this occurs when using RestTemplate, WebClient, or HttpClient with user-controlled URLs, allowing attackers to access internal services, cloud metadata APIs, or other infrastructure.",
        "consequences": "Access internal services not exposed to the internet (Redis, databases, admin panels). Read cloud metadata (AWS IMDSv1: http://169.254.169.254). Port scanning of internal network. In severe cases, remote code execution via internal services.",
        "mitigations": "Validate and sanitize all user-provided URLs. Use allowlists for permitted domains/IPs. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). Disable HTTP redirects. Use network-level controls (egress filtering)."
    },
    # ── #20 — Exposure of Sensitive Information ──────────────────
    {
        "cwe_id": "CWE-200",
        "description": "Exposure of Sensitive Information to an Unauthorized Actor. The product exposes sensitive information to users who are not explicitly authorized to access it. In Spring Boot, this includes detailed error messages with stack traces in production, exposed application.properties, unprotected actuator/env endpoints, or logging sensitive data (passwords, tokens, PII).",
        "consequences": "Disclosure of internal architecture, library versions, database schemas. Exposure of credentials, API keys, or tokens. Leakage of personally identifiable information (PII). Information that helps attackers craft targeted exploits.",
        "mitigations": "Disable detailed error messages in production (server.error.include-stacktrace=never). Protect actuator endpoints. Never log passwords, tokens, or credit card numbers. Use @JsonIgnore on sensitive fields. Implement proper error handling with generic messages."
    },
    # ── #21 — Improper Privilege Management ──────────────────────
    {
        "cwe_id": "CWE-269",
        "description": "Improper Privilege Management. The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control. In Spring Boot, this includes running the application as root, granting excessive database permissions, or assigning overly broad roles.",
        "consequences": "Privilege escalation. If the application is compromised, the attacker inherits excessive permissions. Database compromise via overly permissive DB user.",
        "mitigations": "Follow least privilege principle. Run Spring Boot as a non-root user. Use separate database accounts with minimal permissions. Implement fine-grained roles instead of broad admin/user roles."
    },
    # ── #22 — Code Injection ─────────────────────────────────────
    {
        "cwe_id": "CWE-94",
        "description": "Improper Control of Generation of Code (Code Injection). The product allows user input to be included in code that is dynamically evaluated. In Java/Spring Boot, this includes Expression Language (EL) injection in JSP/Thymeleaf, SpEL injection in @Value or @PreAuthorize, or script engine evaluation (javax.script) with user input.",
        "consequences": "Remote code execution. Full server compromise. Data exfiltration. The attacker can execute arbitrary Java code on the server.",
        "mitigations": "Never evaluate user input as code. Avoid javax.script.ScriptEngine with untrusted input. In SpEL, use SimpleEvaluationContext instead of StandardEvaluationContext. Sanitize all input used in EL expressions."
    },
    # ── #23 — Hardcoded Credentials ──────────────────────────────
    {
        "cwe_id": "CWE-798",
        "description": "Use of Hard-coded Credentials. The product contains hard-coded passwords, API keys, cryptographic keys, or other credentials embedded in the source code. In Spring Boot, this commonly occurs in application.properties/yml files committed to Git, or in Java constants used for JWT secrets, database passwords, or third-party API keys.",
        "consequences": "Complete compromise if source code is leaked or decompiled. Credentials cannot be rotated without code changes. Same credentials used across all environments (dev/staging/prod). Automated scanners (TruffleHog, GitLeaks) can detect these in Git history.",
        "mitigations": "Use environment variables for all secrets. Use Spring Cloud Config Server or HashiCorp Vault for centralized secret management. Use @Value(\"${SECRET}\") with externalized configuration. Add secrets patterns to .gitignore. Use Spring Boot's jasypt for encrypted properties."
    },
    # ── #24 — Uncontrolled Resource Consumption ──────────────────
    {
        "cwe_id": "CWE-400",
        "description": "Uncontrolled Resource Consumption (Resource Exhaustion / DoS). The product does not properly control the allocation and maintenance of a limited resource, allowing an actor to consume resources without bounds. In Spring Boot, this includes unbounded request body sizes, no rate limiting, thread pool exhaustion, or memory-intensive operations without limits.",
        "consequences": "Denial of service (application becomes unresponsive). Server resource exhaustion (CPU, memory, disk, threads). Cascading failures in microservice architectures. Financial cost in cloud environments (autoscaling triggered by attack).",
        "mitigations": "Set spring.servlet.multipart.max-file-size and max-request-size. Implement rate limiting (Bucket4j, Spring Cloud Gateway). Configure connection pool limits. Set timeouts on all external calls (RestTemplate, WebClient). Use pagination for large data sets. Implement circuit breakers (Resilience4j)."
    },
    # ── #25 — Missing Encryption of Sensitive Data ───────────────
    {
        "cwe_id": "CWE-311",
        "description": "Missing Encryption of Sensitive Data. The product does not encrypt sensitive data before storage or transmission, leaving it vulnerable to interception or unauthorized access. In Spring Boot, this includes storing passwords in plaintext, transmitting data over HTTP instead of HTTPS, or using weak encryption algorithms (MD5, SHA-1, DES).",
        "consequences": "Data breach if storage is compromised. Man-in-the-middle attacks on unencrypted connections. Regulatory violations (GDPR, PCI-DSS, HIPAA). Password database compromise.",
        "mitigations": "Enforce HTTPS with HSTS headers. Use BCrypt or Argon2id for password hashing. Use AES-256-GCM for data encryption. Configure Spring Security to require HTTPS (requiresChannel().anyRequest().requiresSecure()). Use TLS 1.3 for all internal communications."
    },
]
