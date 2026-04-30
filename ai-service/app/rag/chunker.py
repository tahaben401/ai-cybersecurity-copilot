"""
MANTIS AI Service — Document Chunker.

Module de découpage intelligent des documents pour le RAG.

Pourquoi le chunking est crucial pour MANTIS ?
    Le modèle d'embedding (bge-base-en-v1.5) a une fenêtre de 512 tokens.
    Si un document fait 2000 tokens, l'embedding ne capture que
    les premiers ~512 tokens et IGNORE le reste.
    → Le chunking garantit que CHAQUE partie du document est vectorisée.

Stratégie de chunking pour la cybersécurité:
    ┌──────────────────────────────────────────────────────────────────┐
    │ Type de document    │ Chunk Size │ Overlap │ Raison             │
    │─────────────────────│────────────│─────────│────────────────────│
    │ CWE entries         │ 512 chars  │ 50      │ Taille modérée     │
    │ CVE advisories      │ 512 chars  │ 50      │ Taille variable    │
    │ OWASP cheatsheets   │ 800 chars  │ 100     │ Documents longs    │
    │ Fix patterns        │ 400 chars  │ 0       │ Courts et atomiques│
    │ Historical findings │ 600 chars  │ 50      │ Context needed     │
    └──────────────────────────────────────────────────────────────────┘

    L'overlap (chevauchement) est important car :
    - Un concept de sécurité peut être à cheval sur 2 chunks
    - Ex: "Use PreparedStatement" à la fin du chunk 1, "with parameterized
      queries to prevent" au début du chunk 2 → Sans overlap, le lien est perdu

Usage:
    from app.rag.chunker import SecurityDocumentChunker

    chunker = SecurityDocumentChunker()
    chunks = chunker.chunk_cwe_entry(cwe_text)
    chunks = chunker.chunk_security_document(long_doc, doc_type="owasp")
"""
from dataclasses import dataclass, field
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.core.logger import logger


@dataclass
class ChunkResult:
    """Résultat du chunking d'un document."""
    chunks: list[str]
    metadatas: list[dict]
    chunk_ids: list[str]
    total_chunks: int = field(init=False)

    def __post_init__(self) -> None:
        self.total_chunks = len(self.chunks)


class SecurityDocumentChunker:
    """
    Chunker spécialisé pour les documents de cybersécurité.

    Adapte la stratégie de chunking selon le type de document,
    car un advisory CVE court n'a pas besoin du même traitement
    qu'un cheatsheet OWASP de 5 pages.
    """

    # ── Séparateurs hiérarchiques ────────────────────────────────────
    # RecursiveCharacterTextSplitter essaie chaque séparateur dans l'ordre.
    # Il split d'abord par \n\n (paragraphes), puis \n (lignes), etc.
    # C'est crucial pour garder le sens des documents de sécurité.
    SECURITY_SEPARATORS = [
        "\n\n",     # Séparation par paragraphe (priorité haute)
        "\n",       # Séparation par ligne
        ". ",       # Séparation par phrase
        ", ",       # Séparation par clause
        " ",        # Séparation par mot (dernier recours)
    ]

    # ── Configurations par type de document ──────────────────────────

    CHUNK_CONFIGS = {
        "cwe_knowledge": {
            "chunk_size": 512,
            "chunk_overlap": 50,
            "description": "CWE entries — taille modérée, overlap léger",
        },
        "cve_advisory": {
            "chunk_size": 512,
            "chunk_overlap": 50,
            "description": "CVE advisories — taille variable",
        },
        "fix_pattern": {
            "chunk_size": 400,
            "chunk_overlap": 0,
            "description": "Fix patterns — courts et atomiques, pas d'overlap",
        },
        "owasp_cheatsheet": {
            "chunk_size": 800,
            "chunk_overlap": 100,
            "description": "OWASP docs — longs, overlap important",
        },
        "historical_finding": {
            "chunk_size": 600,
            "chunk_overlap": 50,
            "description": "Historical findings — contexte nécessaire",
        },
        "default": {
            "chunk_size": 512,
            "chunk_overlap": 50,
            "description": "Configuration par défaut",
        },
    }

    def chunk_document(
        self,
        text: str,
        doc_type: str = "default",
        base_metadata: dict | None = None,
        doc_id: str = "",
    ) -> ChunkResult:
        """
        Découpe un document en chunks optimisés pour le RAG.

        Args:
            text: Contenu textuel du document
            doc_type: Type de document (cwe_knowledge, fix_pattern, etc.)
            base_metadata: Métadonnées à propager sur chaque chunk
            doc_id: ID unique du document source (pour générer les IDs des chunks)

        Returns:
            ChunkResult avec chunks, métadonnées, et IDs
        """
        # Récupérer la config pour ce type
        config = self.CHUNK_CONFIGS.get(doc_type, self.CHUNK_CONFIGS["default"])

        # Si le texte est déjà assez court, pas besoin de chunking
        if len(text) <= config["chunk_size"]:
            metadata = {
                **(base_metadata or {}),
                "chunk_index": 0,
                "total_chunks": 1,
                "doc_type": doc_type,
            }
            chunk_id = f"{doc_id}_chunk_0" if doc_id else None
            return ChunkResult(
                chunks=[text],
                metadatas=[metadata],
                chunk_ids=[chunk_id] if chunk_id else [],
            )

        # Créer le splitter avec la config adaptée
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=config["chunk_size"],
            chunk_overlap=config["chunk_overlap"],
            separators=self.SECURITY_SEPARATORS,
            length_function=len,
            is_separator_regex=False,
        )

        # Découper
        raw_chunks = splitter.split_text(text)

        # Construire les métadonnées et IDs pour chaque chunk
        chunks = []
        metadatas = []
        chunk_ids = []

        for i, chunk in enumerate(raw_chunks):
            # Nettoyer le chunk
            cleaned = chunk.strip()
            if not cleaned or len(cleaned) < 20:
                continue  # Ignorer les chunks trop courts (bruit)

            chunks.append(cleaned)

            metadata = {
                **(base_metadata or {}),
                "chunk_index": i,
                "total_chunks": len(raw_chunks),
                "doc_type": doc_type,
                "chunk_size": len(cleaned),
            }
            metadatas.append(metadata)

            if doc_id:
                chunk_ids.append(f"{doc_id}_chunk_{i}")

        logger.info(
            "document_chunked",
            doc_type=doc_type,
            original_length=len(text),
            chunks_produced=len(chunks),
            chunk_size=config["chunk_size"],
            overlap=config["chunk_overlap"],
        )

        return ChunkResult(
            chunks=chunks,
            metadatas=metadatas,
            chunk_ids=chunk_ids,
        )

    def chunk_cwe_entry(
        self,
        cwe_id: str,
        description: str,
        consequences: str = "",
        mitigations: str = "",
    ) -> ChunkResult:
        """
        Chunke une entrée CWE de manière structurée.

        Formate le texte pour maximiser la qualité du retrieval :
        le CWE ID et la description sont dans chaque chunk.
        """
        text = f"CWE: {cwe_id}\nDescription: {description}"
        if consequences:
            text += f"\nConsequences: {consequences}"
        if mitigations:
            text += f"\nMitigations: {mitigations}"

        return self.chunk_document(
            text=text,
            doc_type="cwe_knowledge",
            base_metadata={
                "type": "cwe_knowledge",
                "cwe_id": cwe_id,
                "source": "mitre_cwe",
            },
            doc_id=f"cwe_{cwe_id}",
        )

    def chunk_fix_pattern(
        self,
        vulnerability_type: str,
        language: str,
        vulnerable_pattern: str,
        secure_pattern: str,
        explanation: str,
    ) -> ChunkResult:
        """
        Chunke un pattern de fix de sécurité.

        Les fix patterns sont généralement courts → souvent 1 seul chunk.
        On ne met PAS d'overlap car chaque pattern doit rester atomique.
        """
        text = (
            f"Vulnerability: {vulnerability_type}\n"
            f"Language: {language}\n"
            f"Vulnerable Code Pattern:\n{vulnerable_pattern}\n"
            f"Secure Code Pattern:\n{secure_pattern}\n"
            f"Explanation: {explanation}"
        )

        fix_id = f"fix_{vulnerability_type.lower().replace(' ', '_')}_{language}"
        return self.chunk_document(
            text=text,
            doc_type="fix_pattern",
            base_metadata={
                "type": "fix_pattern",
                "vulnerability_type": vulnerability_type,
                "language": language,
                "source": "mantis_knowledge",
            },
            doc_id=fix_id,
        )

    def chunk_cve_advisory(
        self,
        cve_id: str,
        description: str,
        cvss_score: float | None = None,
        references: list[str] | None = None,
    ) -> ChunkResult:
        """Chunke un advisory CVE depuis NVD."""
        text = f"CVE: {cve_id}\nDescription: {description}"
        if cvss_score is not None:
            text += f"\nCVSS Score: {cvss_score}"
        if references:
            text += f"\nReferences: {', '.join(references[:3])}"

        return self.chunk_document(
            text=text,
            doc_type="cve_advisory",
            base_metadata={
                "type": "cve_advisory",
                "cve_id": cve_id,
                "cvss_score": cvss_score or 0.0,
                "source": "nvd",
            },
            doc_id=f"cve_{cve_id}",
        )


# ── Singleton ────────────────────────────────────────────────────────
chunker = SecurityDocumentChunker()
