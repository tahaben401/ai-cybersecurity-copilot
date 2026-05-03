from fastapi import Header, HTTPException

from app.core.config import settings
from app.core.logger import logger


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not settings.API_KEY:
        logger.warning("api_key_not_configured")
        return

    if x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
