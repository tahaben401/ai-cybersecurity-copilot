from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.dependencies import require_api_key
from app.cache.semantic_cache import semantic_cache
from app.core.config import settings
from app.core.logger import logger
from app.graph.workflow import process_finding
from app.rag.ingest import ingest_all
from app.rag.vector_store import vector_store
from app.schemas.patch_schema import AIBatchResult, AIAnalysisResult
from app.schemas.sarif_schema import Finding, ScanResultMessage
from app.services.processing import process_scan_message


router = APIRouter()


class AnalyzeRequest(BaseModel):
    scan_id: str
    project_id: str
    finding: Finding


@router.get("/health/live")
def live() -> dict:
    return {"status": "ok"}


@router.get("/health/ready")
def ready() -> dict:
    cache_ok = semantic_cache.is_connected
    rag_ok = vector_store.is_initialized

    if not cache_ok or not rag_ok:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"cache": cache_ok, "rag": rag_ok},
        )

    return {"status": "ok", "cache": cache_ok, "rag": rag_ok}


@router.get("/system/info", dependencies=[Depends(require_api_key)])
def system_info() -> dict:
    return {
        "app_env": settings.APP_ENV,
        "model": settings.LLM_MODEL_NAME,
        "broker_consumer_enabled": settings.BROKER_ENABLE_CONSUMER,
        "broker_prefetch": settings.BROKER_PREFETCH,
        "broker_max_concurrency": settings.BROKER_MAX_CONCURRENCY,
        "queue_in": settings.RABBITMQ_CONSUME_QUEUE,
        "queue_out": settings.RABBITMQ_PUBLISH_QUEUE,
        "cache_connected": semantic_cache.is_connected,
        "rag_initialized": vector_store.is_initialized,
        "rag_documents": vector_store.document_count if vector_store.is_initialized else 0,
    }


@router.post("/rag/ingest", dependencies=[Depends(require_api_key)])
async def rag_ingest() -> dict:
    logger.info("rag_ingest_requested")
    await ingest_all()
    return {
        "status": "ok",
        "documents": vector_store.document_count,
    }


@router.post("/analyze", dependencies=[Depends(require_api_key)], response_model=AIAnalysisResult)
async def analyze(request: AnalyzeRequest) -> AIAnalysisResult:
    finding_dict = request.finding.model_dump(by_alias=True)
    return await process_finding(finding_dict, request.scan_id, request.project_id)


@router.post("/batch", dependencies=[Depends(require_api_key)], response_model=AIBatchResult)
async def analyze_batch(payload: ScanResultMessage) -> AIBatchResult:
    return await process_scan_message(payload)
