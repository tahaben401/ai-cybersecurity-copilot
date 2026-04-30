"""
MANTIS AI Service — Tests Étapes 4 & 5.

Vérification du LLM Factory, Cache, Chunker, et Vector Store Hybride.
"""
import sys
import asyncio
from unittest.mock import patch, MagicMock

# S'assurer que le path est correct
sys.path.insert(0, ".")

from app.core.config import settings

def test_llm_factory():
    print("\n" + "=" * 60)
    print("TEST 1 — LLM Factory & Callbacks")
    print("=" * 60)

    from app.models.factory import get_default_llm, get_coder_llm, get_reviewer_llm
    from app.models.callbacks import TokenTracker

    llm_default = get_default_llm()
    llm_coder = get_coder_llm()
    llm_reviewer = get_reviewer_llm()

    # Vérification des singletons
    assert llm_default is get_default_llm()
    assert llm_coder is get_coder_llm()
    assert llm_reviewer is get_reviewer_llm()

    # Vérification des températures (vérification de la conf interne)
    assert llm_default.temperature == 0.1
    assert llm_coder.temperature == 0.2
    assert llm_reviewer.temperature == 0.0

    tracker = TokenTracker()
    tracker.record(1000, 500)
    assert tracker.total_tokens == 1500
    assert tracker.total_calls == 1

    print("  ✅ LLM Factory & Callbacks PASSED")


async def test_semantic_cache():
    print("\n" + "=" * 60)
    print("TEST 2 — Semantic Cache (Redis)")
    print("=" * 60)

    from app.cache.semantic_cache import semantic_cache

    await semantic_cache.connect()

    # On teste sans Redis (graceful degradation) ou avec si dispo
    if not semantic_cache.is_connected:
        print("  ⚠️ Redis non disponible, test de fallback (graceful degradation)...")
        res = await semantic_cache.get_analysis("rule1")
        assert res is None
        await semantic_cache.set_analysis("rule1", {"test": "ok"})
        print("  ✅ Semantic Cache (Fallback Mode) PASSED")
    else:
        await semantic_cache.set_analysis("rule1", {"status": "ok"}, snippet="test snippet")
        cached = await semantic_cache.get_analysis("rule1", snippet="test snippet")
        assert cached is not None and cached["status"] == "ok"
        print("  ✅ Semantic Cache (Connected) PASSED")
    
    await semantic_cache.close()


def test_chunker():
    print("\n" + "=" * 60)
    print("TEST 3 — Document Chunker")
    print("=" * 60)

    from app.rag.chunker import chunker

    # Test Fix Pattern (pas d'overlap, taille 400)
    long_vuln = "A" * 500
    res = chunker.chunk_fix_pattern("SQLi", "java", long_vuln, "SECURE", "exp")
    
    # Doit avoir été splitté
    assert res.total_chunks >= 2
    assert res.metadatas[0]["doc_type"] == "fix_pattern"
    
    print("  ✅ Document Chunker PASSED")


async def test_vector_store():
    print("\n" + "=" * 60)
    print("TEST 4 — Vector Store (ChromaDB + Hybrid Search)")
    print("=" * 60)

    from app.rag.vector_store import vector_store

    vector_store.initialize()
    assert vector_store.is_initialized

    # Lancer l'ingestion minimale si vide
    if vector_store.document_count == 0:
        print("  ℹ️ Base vectorielle vide, lancement de l'ingestion d'amorçage...")
        from app.rag.ingest import ingest_knowledge
        await ingest_knowledge()

    print(f"  ℹ️ Documents dans la base: {vector_store.document_count}")
    
    # Test recherche sémantique
    print("  🔍 Test Sémantique...")
    res_sem = await vector_store._semantic_search("database query vulnerability", k=2)
    assert len(res_sem) > 0
    print("  ✅ Sémantique OK")

    # Test recherche BM25
    print("  🔍 Test BM25...")
    res_bm25 = await vector_store._bm25_search("CWE-89", k=2)
    assert len(res_bm25) > 0
    print("  ✅ BM25 OK")

    # Test Hybrid Search
    print("  🔍 Test Hybrid Search...")
    res_hybrid = await vector_store.hybrid_search("SQL injection in database", k=3)
    assert len(res_hybrid) > 0
    # Vérifie que la métadonnée 'sources' est présente
    assert "sources" in res_hybrid[0]
    print("  ✅ Hybrid Search OK")
    
    print("  ✅ Vector Store PASSED")


async def main():
    print("🧠 MANTIS AI Service — Tests Étapes 4 & 5")
    print("=" * 60)

    test_llm_factory()
    await test_semantic_cache()
    test_chunker()
    await test_vector_store()

    print("\n" + "=" * 60)
    print("🎉 TOUS LES TESTS PASSENT — Étapes 4 & 5 validées !")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
