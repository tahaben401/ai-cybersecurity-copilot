"""
MANTIS AI Service — Vector Store ChromaDB avec Hybrid Search.

Système RAG avancé combinant :
    1. Recherche Sémantique (ChromaDB + bge-base-en-v1.5)
       → Comprend le SENS : "SQL injection" trouve "database tampering"
    2. Recherche Keyword (BM25)
       → Trouve les TERMES EXACTS : "CWE-89", "PreparedStatement", "A03:2021"

Pourquoi Hybrid Search est crucial pour la cybersécurité ?
    ┌───────────────────────────────────────────────────────────────┐
    │ Requête                  │ Sémantique │ BM25    │ Hybrid   │
    │──────────────────────────│────────────│─────────│──────────│
    │ "SQL injection in Java"  │ ✅ Bon     │ ❌ Moyen │ ✅ Bon   │
    │ "CWE-89"                 │ ❌ Moyen   │ ✅ Exact │ ✅ Exact │
    │ "PreparedStatement fix"  │ ❌ Moyen   │ ✅ Exact │ ✅ Exact │
    │ "database security flaw" │ ✅ Bon     │ ❌ Faible│ ✅ Bon   │
    └───────────────────────────────────────────────────────────────┘

Pourquoi PAS de Re-ranking ?
    - Cross-encoders ajoutent ~200ms par requête
    - Sur 200 findings × 4 agents = +160 secondes de latence
    - Nos documents sont bien structurés → la pertinence initiale suffit
    - bge-base-en-v1.5 est déjà un modèle de retrieval optimisé
    - Le LLM agent fait son propre "re-ranking" en analysant le contexte

Architecture:
    Query
    ├── ChromaDB (Semantic) → Top K résultats par similarité vectorielle
    ├── BM25 (Keyword) → Top K résultats par correspondance de termes
    └── Fusion RRF → Résultats combinés et dédupliqués
         └── Reciprocal Rank Fusion pondère les deux sources
"""
from pathlib import Path
from typing import Any

import chromadb
from langchain_chroma import Chroma
from langchain_community.retrievers import BM25Retriever
from langchain_core.documents import Document

from app.core.config import settings
from app.core.logger import logger
from app.core.exceptions import RAGRetrievalError
from app.rag.embeddings import get_embeddings
from app.rag.chunker import chunker, ChunkResult


class MantisVectorStore:
    """
    Vector Store hybride pour le RAG de MANTIS.

    Combine ChromaDB (sémantique) et BM25 (keyword) pour une
    recherche optimale dans le contexte cybersécurité.
    """

    def __init__(self) -> None:
        self._store: Chroma | None = None
        self._client: chromadb.ClientAPI | None = None
        self._initialized: bool = False
        # BM25 index — construit à partir des documents ChromaDB
        self._bm25_documents: list[Document] = []
        self._bm25_dirty: bool = True  # Flag pour reconstruire l'index BM25

    def initialize(self) -> None:
        """
        Initialise ChromaDB avec persistance locale et charge le BM25 index.
        """
        try:
            persist_dir = settings.chroma_persist_path
            persist_dir.mkdir(parents=True, exist_ok=True)

            self._client = chromadb.PersistentClient(path=str(persist_dir))

            embeddings = get_embeddings()
            self._store = Chroma(
                client=self._client,
                collection_name=settings.CHROMA_COLLECTION_NAME,
                embedding_function=embeddings,
            )

            self._initialized = True

            doc_count = self.document_count

            # Charger les documents existants pour BM25
            if doc_count > 0:
                self._load_bm25_documents()

            logger.info(
                "chromadb_initialized",
                persist_dir=str(persist_dir),
                collection=settings.CHROMA_COLLECTION_NAME,
                documents=doc_count,
                hybrid_search="enabled",
            )

        except Exception as e:
            self._initialized = False
            logger.error("chromadb_init_failed", error=str(e))
            raise RAGRetrievalError(f"ChromaDB initialization: {e}")

    @property
    def is_initialized(self) -> bool:
        return self._initialized and self._store is not None

    @property
    def document_count(self) -> int:
        if not self._client:
            return 0
        try:
            collection = self._client.get_or_create_collection(
                name=settings.CHROMA_COLLECTION_NAME
            )
            return collection.count()
        except Exception:
            return 0

    # ── BM25 Index Management ────────────────────────────────────────

    def _load_bm25_documents(self) -> None:
        """
        Charge tous les documents depuis ChromaDB pour construire l'index BM25.

        On fait ça au démarrage et après chaque ajout de documents.
        C'est rapide car BM25 est un index léger en mémoire.
        """
        if not self._store:
            return

        try:
            collection = self._client.get_or_create_collection(
                name=settings.CHROMA_COLLECTION_NAME
            )

            # Récupérer tous les documents
            all_data = collection.get(include=["documents", "metadatas"])
            documents = all_data.get("documents", [])
            metadatas = all_data.get("metadatas", [])
            ids = all_data.get("ids", [])

            self._bm25_documents = []
            for i, doc_text in enumerate(documents):
                if doc_text:
                    metadata = metadatas[i] if metadatas and i < len(metadatas) else {}
                    metadata["_id"] = ids[i] if ids and i < len(ids) else str(i)
                    self._bm25_documents.append(
                        Document(page_content=doc_text, metadata=metadata)
                    )

            self._bm25_dirty = False
            logger.info(
                "bm25_index_loaded",
                documents=len(self._bm25_documents),
            )

        except Exception as e:
            logger.warning("bm25_index_load_failed", error=str(e))
            self._bm25_documents = []

    def _get_bm25_retriever(self, k: int = 5) -> BM25Retriever | None:
        """Construit un BM25Retriever à partir des documents en mémoire."""
        if not self._bm25_documents:
            return None

        if self._bm25_dirty:
            self._load_bm25_documents()

        try:
            retriever = BM25Retriever.from_documents(
                self._bm25_documents,
                k=k,
            )
            return retriever
        except Exception as e:
            logger.warning("bm25_retriever_creation_failed", error=str(e))
            return None

    # ── Hybrid Search (Cœur du RAG) ──────────────────────────────────

    async def hybrid_search(
        self,
        query: str,
        k: int = 5,
        semantic_weight: float = 0.6,
        keyword_weight: float = 0.4,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Recherche hybride : Sémantique (ChromaDB) + Keyword (BM25).

        Utilise Reciprocal Rank Fusion (RRF) pour combiner les résultats.
        RRF est simple, robuste, et ne nécessite PAS de calibration.

        Formule RRF:
            score(d) = Σ 1 / (k + rank_i(d))
            où k = 60 (constante standard), rank_i = rang dans la source i

        Args:
            query: Texte de recherche
            k: Nombre de résultats finaux
            semantic_weight: Poids de la recherche sémantique (0-1)
            keyword_weight: Poids de la recherche keyword (0-1)
            filter_metadata: Filtres optionnels sur les métadonnées

        Returns:
            Liste de résultats triés par score RRF combiné
        """
        if not self.is_initialized:
            logger.warning("vector_store_not_initialized")
            return []

        results_map: dict[str, dict[str, Any]] = {}

        # ── 1. Recherche Sémantique (ChromaDB) ──────────────────────
        semantic_results = await self._semantic_search(
            query, k=k * 2, filter_metadata=filter_metadata
        )

        for rank, result in enumerate(semantic_results):
            content = result["content"]
            content_key = content[:100]  # Clé de déduplication
            rrf_score = semantic_weight * (1.0 / (60 + rank))

            if content_key in results_map:
                results_map[content_key]["rrf_score"] += rrf_score
                results_map[content_key]["sources"].append("semantic")
            else:
                results_map[content_key] = {
                    "content": content,
                    "metadata": result["metadata"],
                    "rrf_score": rrf_score,
                    "semantic_score": result.get("relevance_score", 0.0),
                    "sources": ["semantic"],
                }

        # ── 2. Recherche Keyword (BM25) ──────────────────────────────
        bm25_results = await self._bm25_search(query, k=k * 2)

        for rank, result in enumerate(bm25_results):
            content = result["content"]
            content_key = content[:100]
            rrf_score = keyword_weight * (1.0 / (60 + rank))

            if content_key in results_map:
                results_map[content_key]["rrf_score"] += rrf_score
                results_map[content_key]["sources"].append("bm25")
            else:
                results_map[content_key] = {
                    "content": content,
                    "metadata": result["metadata"],
                    "rrf_score": rrf_score,
                    "semantic_score": 0.0,
                    "sources": ["bm25"],
                }

        # ── 3. Trier par score RRF et limiter à k ───────────────────
        sorted_results = sorted(
            results_map.values(),
            key=lambda x: x["rrf_score"],
            reverse=True,
        )[:k]

        # Compter les sources pour le log
        hybrid_count = sum(1 for r in sorted_results if len(r["sources"]) > 1)

        logger.info(
            "hybrid_search_completed",
            query_preview=query[:80],
            total_results=len(sorted_results),
            hybrid_matches=hybrid_count,
            semantic_only=sum(1 for r in sorted_results if r["sources"] == ["semantic"]),
            bm25_only=sum(1 for r in sorted_results if r["sources"] == ["bm25"]),
        )

        return sorted_results

    async def _semantic_search(
        self,
        query: str,
        k: int = 10,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Recherche sémantique pure via ChromaDB."""
        if not self._store:
            return []

        try:
            if filter_metadata:
                docs_with_scores = self._store.similarity_search_with_relevance_scores(
                    query, k=k, filter=filter_metadata
                )
            else:
                docs_with_scores = self._store.similarity_search_with_relevance_scores(
                    query, k=k
                )

            return [
                {
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "relevance_score": round(score, 4),
                }
                for doc, score in docs_with_scores
            ]

        except Exception as e:
            logger.warning("semantic_search_failed", error=str(e))
            return []

    async def _bm25_search(
        self,
        query: str,
        k: int = 10,
    ) -> list[dict[str, Any]]:
        """Recherche keyword pure via BM25."""
        retriever = self._get_bm25_retriever(k=k)
        if not retriever:
            return []

        try:
            docs = retriever.invoke(query)
            return [
                {
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                }
                for doc in docs
            ]
        except Exception as e:
            logger.warning("bm25_search_failed", error=str(e))
            return []

    # ── Méthodes de recherche spécialisées ───────────────────────────

    async def search_similar(
        self,
        query: str,
        k: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Point d'entrée principal de recherche — utilise l'hybride.

        Fallback automatique sur le sémantique pur si BM25 non disponible.
        """
        if self._bm25_documents:
            return await self.hybrid_search(query, k=k, filter_metadata=filter_metadata)
        return await self._semantic_search(query, k=k, filter_metadata=filter_metadata)

    async def search_by_cwe(self, cwe_id: str, k: int = 5) -> list[dict[str, Any]]:
        """
        Recherche hybride spécialisée par CWE.

        Le BM25 excelle ici car "CWE-89" est un terme exact.
        """
        query = f"{cwe_id} vulnerability weakness remediation mitigation"
        return await self.hybrid_search(query, k=k, keyword_weight=0.5, semantic_weight=0.5)

    async def search_fix_patterns(
        self,
        vulnerability_type: str,
        language: str = "java",
        k: int = 3,
    ) -> list[dict[str, Any]]:
        """Recherche hybride pour les patterns de fix."""
        query = f"Security fix pattern for {vulnerability_type} in {language} code"
        return await self.hybrid_search(
            query,
            k=k,
            filter_metadata={"type": "fix_pattern"},
            semantic_weight=0.7,
            keyword_weight=0.3,
        )

    # ── Ajout de documents (avec chunking) ───────────────────────────

    async def add_documents(
        self,
        texts: list[str],
        metadatas: list[dict[str, Any]] | None = None,
        ids: list[str] | None = None,
    ) -> int:
        """
        Ajoute des documents au vector store.

        Marque le BM25 index comme dirty pour reconstruction au prochain search.
        """
        if not self.is_initialized:
            logger.warning("vector_store_not_initialized", action="add")
            return 0

        try:
            if ids:
                self._store.add_texts(texts, metadatas=metadatas, ids=ids)
            else:
                self._store.add_texts(texts, metadatas=metadatas)

            # Marquer le BM25 comme dirty (reconstruction au prochain search)
            self._bm25_dirty = True

            count = len(texts)
            logger.info("documents_added", count=count, total=self.document_count)
            return count

        except Exception as e:
            logger.error("document_add_failed", error=str(e))
            return 0

    async def add_chunked_document(self, chunk_result: ChunkResult) -> int:
        """
        Ajoute un document pré-chunké au vector store.

        Utilise les résultats du SecurityDocumentChunker.
        """
        return await self.add_documents(
            texts=chunk_result.chunks,
            metadatas=chunk_result.metadatas,
            ids=chunk_result.chunk_ids if chunk_result.chunk_ids else None,
        )

    async def add_cwe_knowledge(
        self,
        cwe_id: str,
        description: str,
        consequences: str = "",
        mitigations: str = "",
    ) -> int:
        """Ajoute une entrée CWE avec chunking automatique."""
        chunk_result = chunker.chunk_cwe_entry(cwe_id, description, consequences, mitigations)
        return await self.add_chunked_document(chunk_result)

    async def add_fix_pattern(
        self,
        vulnerability_type: str,
        language: str,
        vulnerable_pattern: str,
        secure_pattern: str,
        explanation: str,
    ) -> int:
        """Ajoute un pattern de fix avec chunking automatique."""
        chunk_result = chunker.chunk_fix_pattern(
            vulnerability_type, language, vulnerable_pattern, secure_pattern, explanation
        )
        return await self.add_chunked_document(chunk_result)

    async def add_cve_advisory(
        self,
        cve_id: str,
        description: str,
        cvss_score: float | None = None,
        references: list[str] | None = None,
    ) -> int:
        """Ajoute un advisory CVE avec chunking automatique."""
        chunk_result = chunker.chunk_cve_advisory(cve_id, description, cvss_score, references)
        return await self.add_chunked_document(chunk_result)

    async def add_historical_finding(
        self,
        rule_id: str,
        analysis: str,
        patch_code: str,
        was_approved: bool,
    ) -> int:
        """
        Sauvegarde un résultat pour l'apprentissage.
        Ne stocke QUE les patches approuvés.
        """
        if not was_approved:
            return 0

        text = (
            f"Rule: {rule_id}\n"
            f"Analysis: {analysis}\n"
            f"Approved Patch:\n{patch_code}"
        )
        chunk_result = chunker.chunk_document(
            text=text,
            doc_type="historical_finding",
            base_metadata={
                "type": "historical_finding",
                "rule_id": rule_id,
                "approved": True,
                "source": "mantis_pipeline",
            },
        )
        return await self.add_chunked_document(chunk_result)

    # ── Utilitaires ──────────────────────────────────────────────────

    def rebuild_bm25_index(self) -> None:
        """Force la reconstruction de l'index BM25."""
        self._bm25_dirty = True
        self._load_bm25_documents()

    async def get_stats(self) -> dict[str, Any]:
        """Statistiques du vector store."""
        return {
            "initialized": self.is_initialized,
            "total_documents": self.document_count,
            "bm25_documents": len(self._bm25_documents),
            "hybrid_search": len(self._bm25_documents) > 0,
            "collection": settings.CHROMA_COLLECTION_NAME,
            "persist_dir": str(settings.chroma_persist_path),
        }


# ── Singleton ────────────────────────────────────────────────────────
vector_store = MantisVectorStore()
