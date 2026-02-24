import asyncio
import logging
import redis

from app.core.config import settings
from app.schema.detection import LogMessage
from app.service.rule_engine import run_all_rules
from app.service.ai_analyzer import analyze_with_llm
from app.service.event_store import save_security_event

logger = logging.getLogger(__name__)

# Buffer for AI batch analysis
_log_buffer: list[LogMessage] = []
AI_BATCH_SIZE = 10


def create_redis_client() -> redis.Redis:
    return redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        decode_responses=True,
    )


def ensure_consumer_group(r: redis.Redis):
    """Create consumer group if it doesn't exist."""
    try:
        r.xgroup_create(
            settings.REDIS_STREAM_KEY,
            settings.REDIS_CONSUMER_GROUP,
            id="0",
            mkstream=True,
        )
        logger.info(f"Created consumer group: {settings.REDIS_CONSUMER_GROUP}")
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" in str(e):
            logger.debug("Consumer group already exists")
        else:
            raise


def parse_stream_entry(data: dict) -> LogMessage:
    """Parse Redis Stream entry into LogMessage."""
    return LogMessage(
        id=data.get("id", ""),
        timestamp=data.get("timestamp", ""),
        source=data.get("source", ""),
        log_level=data.get("logLevel", "INFO"),
        message=data.get("message", ""),
        source_ip=data.get("sourceIp", ""),
        user_id=data.get("userId", ""),
        endpoint=data.get("endpoint", ""),
        method=data.get("method", ""),
        status_code=data.get("statusCode", ""),
    )


def _blocking_read(r: redis.Redis):
    """Blocking Redis read - runs in thread pool to avoid blocking event loop."""
    return r.xreadgroup(
        groupname=settings.REDIS_CONSUMER_GROUP,
        consumername=settings.REDIS_CONSUMER_NAME,
        streams={settings.REDIS_STREAM_KEY: ">"},
        count=10,
        block=3000,
    )


async def process_log(log: LogMessage, db_session):
    """Process a single log entry through rule engine."""
    detections = run_all_rules(log)

    for detection in detections:
        await save_security_event(detection, db_session)
        logger.info(f"Security event created: type={detection['event_type']}, severity={detection['severity']}")

    _log_buffer.append(log)


async def flush_ai_buffer(db_session):
    """Send buffered logs to AI for analysis."""
    global _log_buffer

    if not _log_buffer:
        return

    logs_to_analyze = _log_buffer.copy()
    _log_buffer.clear()

    ai_detections = await analyze_with_llm(logs_to_analyze)

    for detection in ai_detections:
        await save_security_event(detection, db_session)
        logger.info(f"AI detection: type={detection['event_type']}, confidence={detection['confidence']}")


async def consume_logs(db_session):
    """Main consumer loop: read from Redis Stream and process logs."""
    r = create_redis_client()
    ensure_consumer_group(r)

    logger.info("Starting Redis Stream consumer...")

    # Yield control so uvicorn startup can complete
    await asyncio.sleep(0)

    while True:
        try:
            # Run blocking Redis read in thread pool
            entries = await asyncio.to_thread(_blocking_read, r)

            if entries:
                for stream_name, messages in entries:
                    for msg_id, data in messages:
                        log = parse_stream_entry(data)
                        await process_log(log, db_session)
                        r.xack(settings.REDIS_STREAM_KEY, settings.REDIS_CONSUMER_GROUP, msg_id)

            if len(_log_buffer) >= AI_BATCH_SIZE:
                await flush_ai_buffer(db_session)

        except asyncio.CancelledError:
            logger.info("Consumer task cancelled")
            break
        except Exception as e:
            logger.error(f"Consumer error: {e}")
            await asyncio.sleep(5)
