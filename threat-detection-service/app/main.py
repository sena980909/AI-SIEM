import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import settings
from app.core.database import SessionLocal
from app.api.detection import router as detection_router
from app.service.stream_consumer import consume_logs, flush_ai_buffer

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background consumer on app startup, cleanup on shutdown."""
    logger.info("Starting Threat Detection Service...")

    db = SessionLocal()
    consumer_task = asyncio.create_task(consume_logs(db))

    # Periodic AI buffer flush
    async def periodic_flush():
        while True:
            await asyncio.sleep(60)
            await flush_ai_buffer(db)

    flush_task = asyncio.create_task(periodic_flush())

    yield

    consumer_task.cancel()
    flush_task.cancel()
    db.close()
    logger.info("Threat Detection Service stopped")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.include_router(detection_router)


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}
