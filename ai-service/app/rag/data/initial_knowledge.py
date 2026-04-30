"""
MANTIS AI Service — Base de connaissances initiale.

Données d'amorçage (seed data) pour le RAG ChromaDB.
Contient les vulnérabilités les plus courantes et leurs patterns de correction
en Java (Spring Boot) pour donner au Coder Agent une base solide dès le départ.
c'est seulement pour le test , puis je doit cree une base de conaissance plus complete de niveau entreprise en utilisant des techniques de RAG avancer .
"""

CWE_KNOWLEDGE = [
    {
        "cwe_id": "CWE-89",
        "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'). The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "consequences": "Attackers can read, modify, or delete database contents. They may bypass authentication, execute administrative operations, or recover file system contents.",
        "mitigations": "Use Prepared Statements (Parameterized Queries). Use Stored Procedures. Escaping all User Supplied Input. Use Least Privilege."
    },
    {
        "cwe_id": "CWE-79",
        "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'). The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
        "consequences": "Attackers can execute malicious scripts in the victim's browser, leading to session hijacking, defacement, or redirection to malicious sites.",
        "mitigations": "Context-Aware Output Encoding. Use HTTPOnly flag on cookies. Implement Content Security Policy (CSP)."
    },
    {
        "cwe_id": "CWE-22",
        "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'). The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
        "consequences": "Attackers can read or overwrite sensitive files on the file system, such as configuration files, passwords, or source code.",
        "mitigations": "Use absolute paths or strictly validate input against an allowlist of permitted filenames. Ensure the resolved path resides within the intended directory."
    },
    {
        "cwe_id": "CWE-611",
        "description": "Improper Restriction of XML External Entity Reference ('XXE'). The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
        "consequences": "Attackers can extract data, execute server-side request forgery (SSRF), or cause a denial of service.",
        "mitigations": "Disable processing of XML External Entities (XXE) and DTDs in the XML parser configuration."
    }
]

FIX_PATTERNS = [
    {
        "vulnerability_type": "SQL Injection",
        "language": "java",
        "vulnerable_pattern": "String query = \"SELECT * FROM users WHERE username = '\" + username + \"'\";\nStatement statement = connection.createStatement();\nResultSet resultSet = statement.executeQuery(query);",
        "secure_pattern": "String query = \"SELECT * FROM users WHERE username = ?\";\nPreparedStatement pstmt = connection.prepareStatement(query);\npstmt.setString(1, username);\nResultSet resultSet = pstmt.executeQuery();",
        "explanation": "Utilisation de PreparedStatement. Les paramètres sont envoyés au serveur de base de données séparément de la requête SQL, empêchant toute injection sémantique de code."
    },
    {
        "vulnerability_type": "Path Traversal",
        "language": "java",
        "vulnerable_pattern": "File file = new File(BASE_DIR, userInput);\nInputStream is = new FileInputStream(file);",
        "secure_pattern": "File file = new File(BASE_DIR, userInput);\nif (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {\n    throw new SecurityException(\"Invalid file path\");\n}\nInputStream is = new FileInputStream(file);",
        "explanation": "Validation du chemin canonique. getCanonicalPath() résout les '..' et '.' permettant de vérifier si le chemin final reste bien à l'intérieur du répertoire de base autorisé."
    },
    {
        "vulnerability_type": "XXE",
        "language": "java",
        "vulnerable_pattern": "DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();\nDocument doc = builder.parse(inputStream);",
        "secure_pattern": "DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nfactory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\nfactory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\nDocumentBuilder builder = factory.newDocumentBuilder();\nDocument doc = builder.parse(inputStream);",
        "explanation": "Désactivation complète du support DTD et des entités externes (générales et paramètres) dans le DocumentBuilderFactory pour prévenir les attaques XXE."
    }
]
