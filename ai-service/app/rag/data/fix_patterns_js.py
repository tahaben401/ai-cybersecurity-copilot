"""
MANTIS AI Service — Fix Patterns JavaScript/TypeScript (Node.js/Express).

Patterns de correction sécurisée pour JS/TS.
"""

FIX_PATTERNS_JS = [
    # ── SQL Injection (Node.js) ──────────────────────────────────
    {
        "vulnerability_type": "SQL Injection",
        "language": "javascript",
        "vulnerable_pattern": (
            'const query = `SELECT * FROM users WHERE username = \'${username}\'`;\n'
            'db.query(query, (err, results) => { ... });'
        ),
        "secure_pattern": (
            'const query = "SELECT * FROM users WHERE username = ?";\n'
            'db.query(query, [username], (err, results) => { ... });'
        ),
        "explanation": "Never interpolate user input directly into SQL strings. Use parameterized queries provided by libraries like mysql2 or pg. Pass inputs as an array in the second argument."
    },
    # ── NoSQL Injection (MongoDB) ────────────────────────────────
    {
        "vulnerability_type": "NoSQL Injection",
        "language": "javascript",
        "vulnerable_pattern": (
            'app.post("/login", async (req, res) => {\n'
            '  // Attacker sends: {"username": {"$gt": ""}, "password": {"$gt": ""}}\n'
            '  const user = await User.findOne({\n'
            '    username: req.body.username,\n'
            '    password: req.body.password\n'
            '  });\n'
            '});'
        ),
        "secure_pattern": (
            'const mongoSanitize = require("express-mongo-sanitize");\n'
            'app.use(mongoSanitize()); // Prevent injection at middleware level\n\n'
            'app.post("/login", async (req, res) => {\n'
            '  // Force casting to string to prevent object injection\n'
            '  const user = await User.findOne({\n'
            '    username: String(req.body.username),\n'
            '    password: String(req.body.password)\n'
            '  });\n'
            '});'
        ),
        "explanation": "MongoDB is vulnerable to NoSQL injection if an attacker sends an object with operators (like $gt, $ne) instead of a string. Force cast inputs to String, and use middleware like express-mongo-sanitize."
    },
    # ── Command Injection (Node.js) ──────────────────────────────
    {
        "vulnerability_type": "OS Command Injection",
        "language": "javascript",
        "vulnerable_pattern": (
            'const { exec } = require("child_process");\n'
            'exec(`ping -c 1 ${hostname}`, (err, stdout, stderr) => { ... });'
        ),
        "secure_pattern": (
            'const { execFile } = require("child_process");\n'
            'execFile("ping", ["-c", "1", hostname], (err, stdout, stderr) => { ... });'
        ),
        "explanation": "Avoid child_process.exec() because it spawns a shell. Use execFile() or spawn() which pass arguments as an array directly to the executable, bypassing the shell."
    },
    # ── Cross-Site Scripting (XSS in React) ──────────────────────
    {
        "vulnerability_type": "Cross-Site Scripting XSS",
        "language": "javascript",
        "vulnerable_pattern": (
            'function HtmlViewer({ userHtml }) {\n'
            '  return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;\n'
            '}'
        ),
        "secure_pattern": (
            'import DOMPurify from "dompurify";\n\n'
            'function HtmlViewer({ userHtml }) {\n'
            '  const cleanHtml = DOMPurify.sanitize(userHtml);\n'
            '  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;\n'
            '}'
        ),
        "explanation": "React protects against XSS by default, but dangerouslySetInnerHTML bypasses this. If you must render raw HTML, sanitize it first using a library like DOMPurify."
    },
    # ── Path Traversal (Express) ─────────────────────────────────
    {
        "vulnerability_type": "Path Traversal",
        "language": "javascript",
        "vulnerable_pattern": (
            'const path = require("path");\n'
            'app.get("/files/:filename", (req, res) => {\n'
            '  const filepath = path.join(__dirname, "uploads", req.params.filename);\n'
            '  res.sendFile(filepath);\n'
            '});'
        ),
        "secure_pattern": (
            'const path = require("path");\n'
            'app.get("/files/:filename", (req, res) => {\n'
            '  const rootDir = path.join(__dirname, "uploads");\n'
            '  // path.join normalizes the path\n'
            '  const filepath = path.join(rootDir, req.params.filename);\n'
            '  \n'
            '  // Verify the resolved path starts with the intended directory\n'
            '  if (!filepath.startsWith(rootDir)) {\n'
            '    return res.status(403).send("Forbidden");\n'
            '  }\n'
            '  res.sendFile(filepath);\n'
            '});'
        ),
        "explanation": "User input in file paths can lead to directory traversal (e.g., filename='../../../etc/passwd'). Normalize the path and strictly verify it starts with the intended base directory."
    },
]
