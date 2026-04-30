"""
MANTIS AI Service — Script d'Ingestion RAG (Production).

Ce script peuple la base vectorielle ChromaDB avec TOUTE la connaissance
de sécurité nécessaire pour que les agents soient efficaces :
    - 25 CWEs (MITRE Top 25)
    - 15 Fix Patterns Java/Spring Boot
    - 8 OWASP Cheatsheets

Usage:
    python -m app.rag.ingest
"""
import asyncio
from app.core.logger import logger
from app.rag.vector_store import vector_store
from app.rag.chunker import chunker

# ── Sources de données ───────────────────────────────────────────────
from app.rag.data.cwe_top25 import CWE_TOP_25
from app.rag.data.fix_patterns_java import FIX_PATTERNS_JAVA
from app.rag.data.fix_patterns_python import FIX_PATTERNS_PYTHON
from app.rag.data.fix_patterns_js import FIX_PATTERNS_JS
from app.rag.data.owasp_cheatsheets import OWASP_CHEATSHEETS


async def ingest_cwe_knowledge() -> int:
    """Ingère les 25 CWEs les plus dangereuses."""
    logger.info("ingesting_cwe_top25", count=len(CWE_TOP_25))
    total = 0
    for cwe in CWE_TOP_25:
        count = await vector_store.add_cwe_knowledge(
            cwe_id=cwe["cwe_id"],
            description=cwe["description"],
            consequences=cwe["consequences"],
            mitigations=cwe["mitigations"],
        )
        total += count
    return total


async def ingest_fix_patterns() -> int:
    """Ingère les patterns de correction multi-langages."""
    all_patterns = FIX_PATTERNS_JAVA + FIX_PATTERNS_PYTHON + FIX_PATTERNS_JS
    logger.info("ingesting_fix_patterns", count=len(all_patterns))
    total = 0
    for fix in all_patterns:
        count = await vector_store.add_fix_pattern(
            vulnerability_type=fix["vulnerability_type"],
            language=fix["language"],
            vulnerable_pattern=fix["vulnerable_pattern"],
            secure_pattern=fix["secure_pattern"],
            explanation=fix["explanation"],
        )
        total += count
    return total


async def ingest_owasp_cheatsheets() -> int:
    """Ingère les cheatsheets OWASP pour Java/Spring Boot."""
    logger.info("ingesting_owasp_cheatsheets", count=len(OWASP_CHEATSHEETS))
    total = 0
    for sheet in OWASP_CHEATSHEETS:
        chunk_result = chunker.chunk_document(
            text=f"OWASP Cheatsheet: {sheet['topic']}\n"
                 f"Category: {sheet['category']}\n\n"
                 f"{sheet['content']}",
            doc_type="owasp_cheatsheet",
            base_metadata={
                "type": "owasp_cheatsheet",
                "topic": sheet["topic"],
                "category": sheet["category"],
                "source": "owasp",
            },
            doc_id=f"owasp_{sheet['topic'].lower().replace(' ', '_')}",
        )
        count = await vector_store.add_chunked_document(chunk_result)
        total += count
    return total


async def ingest_all():
    """Point d'entrée principal — ingère TOUTES les données RAG."""
    logger.info("rag_full_ingestion_started")

    # Initialiser ChromaDB
    vector_store.initialize()
    initial_count = vector_store.document_count

    # Si la base a déjà des documents, on la réinitialise
    if initial_count > 0:
        logger.info("clearing_existing_data", count=initial_count)
        # On réinitialise via le client ChromaDB directement
        if vector_store._client:
            try:
                vector_store._client.delete_collection("mantis-cve-knowledge")
                logger.info("collection_deleted")
            except Exception:
                pass
            # Réinitialiser le store
            vector_store._initialized = False
            vector_store.initialize()

    # Ingestion des 3 sources
    cwe_count = await ingest_cwe_knowledge()
    fix_count = await ingest_fix_patterns()
    owasp_count = await ingest_owasp_cheatsheets()

    # Reconstruire l'index BM25
    vector_store.rebuild_bm25_index()

    total = cwe_count + fix_count + owasp_count
    logger.info(
        "rag_full_ingestion_completed",
        cwe_chunks=cwe_count,
        fix_chunks=fix_count,
        owasp_chunks=owasp_count,
        total_chunks=total,
        total_documents=vector_store.document_count,
    )

    print(f"\n{'='*60}")
    print(f"  MANTIS RAG — Ingestion Complete")
    print(f"{'='*60}")
    print(f"  CWE Top 25:         {cwe_count} chunks")
    print(f"  Fix Patterns Java:  {fix_count} chunks")
    print(f"  OWASP Cheatsheets:  {owasp_count} chunks")
    print(f"  {'─'*40}")
    print(f"  TOTAL:              {total} chunks in ChromaDB")
    print(f"  BM25 Index:         {len(vector_store._bm25_documents)} documents")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(ingest_all())
