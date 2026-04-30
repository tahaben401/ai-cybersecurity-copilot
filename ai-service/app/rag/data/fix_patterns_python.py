"""
MANTIS AI Service — Fix Patterns Python (Django/Flask).

Patterns de correction sécurisée pour Python.
"""

FIX_PATTERNS_PYTHON = [
    # ── SQL Injection (Raw SQL in Django/Flask) ────────────────
    {
        "vulnerability_type": "SQL Injection",
        "language": "python",
        "vulnerable_pattern": (
            'query = f"SELECT * FROM users WHERE username = \'{username}\'"\n'
            'cursor.execute(query)'
        ),
        "secure_pattern": (
            'query = "SELECT * FROM users WHERE username = %s"\n'
            'cursor.execute(query, (username,))'
        ),
        "explanation": "Never use f-strings or string formatting for SQL queries. Use parameterized queries provided by the database driver (like psycopg2 or sqlite3). Pass parameters as a separate tuple."
    },
    # ── Command Injection ────────────────────────────────────────
    {
        "vulnerability_type": "OS Command Injection",
        "language": "python",
        "vulnerable_pattern": (
            'import os\n'
            'os.system(f"ping -c 1 {hostname}")'
        ),
        "secure_pattern": (
            'import subprocess\n'
            'subprocess.run(["ping", "-c", "1", hostname], check=True)'
        ),
        "explanation": "Avoid os.system() and subprocess with shell=True. Use subprocess.run() with a list of arguments. This bypasses the shell entirely, making command injection impossible."
    },
    # ── Path Traversal ───────────────────────────────────────────
    {
        "vulnerability_type": "Path Traversal",
        "language": "python",
        "vulnerable_pattern": (
            'import os\n'
            'filename = request.args.get("file")\n'
            'filepath = os.path.join(UPLOAD_DIR, filename)\n'
            'with open(filepath, "r") as f:\n'
            '    return f.read()'
        ),
        "secure_pattern": (
            'import os\n'
            'from werkzeug.utils import secure_filename\n\n'
            'filename = secure_filename(request.args.get("file"))\n'
            'filepath = os.path.join(UPLOAD_DIR, filename)\n'
            'with open(filepath, "r") as f:\n'
            '    return f.read()'
        ),
        "explanation": "Use werkzeug.utils.secure_filename() or os.path.basename() to strip path traversal sequences ('../') and extract only the safe file name."
    },
    # ── Insecure Deserialization (Pickle) ────────────────────────
    {
        "vulnerability_type": "Insecure Deserialization",
        "language": "python",
        "vulnerable_pattern": (
            'import pickle\n'
            'data = request.get_data()\n'
            'obj = pickle.loads(data)'
        ),
        "secure_pattern": (
            'import json\n'
            'data = request.get_data(as_text=True)\n'
            'obj = json.loads(data)'
        ),
        "explanation": "Never use the pickle module with untrusted data. Pickle allows arbitrary code execution during deserialization. Use safe formats like JSON instead."
    },
    # ── XXE (XML External Entity) ────────────────────────────────
    {
        "vulnerability_type": "XXE",
        "language": "python",
        "vulnerable_pattern": (
            'from lxml import etree\n'
            'xml_data = request.get_data()\n'
            'tree = etree.fromstring(xml_data)'
        ),
        "secure_pattern": (
            'from defusedxml.lxml import fromstring\n'
            'xml_data = request.get_data()\n'
            'tree = fromstring(xml_data)'
        ),
        "explanation": "Standard XML libraries in Python are vulnerable to XXE. Use the defusedxml library, which overrides standard library parsers with safe defaults that disable external entity resolution."
    },
]
