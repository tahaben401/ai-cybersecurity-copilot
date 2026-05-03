import asyncio

from fastapi import FastAPI

from app.api.routes import router as api_router
from app.broker.consumer import consumer
from app.cache.semantic_cache import semantic_cache
from app.core.config import settings
from app.core.logger import logger
from app.rag.vector_store import vector_store


app = FastAPI(title="MANTIS AI Service")
app.include_router(api_router)


@app.on_event("startup")
async def on_startup() -> None:
    logger.info("ai_service_starting", env=settings.APP_ENV)

    await semantic_cache.connect()
    if not vector_store.is_initialized:
        vector_store.initialize()

    if settings.BROKER_ENABLE_CONSUMER:
        asyncio.create_task(consumer.start())
        logger.info("broker_consumer_spawned")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    if settings.BROKER_ENABLE_CONSUMER:
        await consumer.stop()
    await semantic_cache.close()
    logger.info("ai_service_stopped")
