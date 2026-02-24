import logging
import json
import httpx
import anthropic

from app.core.config import settings
from app.schema.detection import LogMessage, EventType, Severity

logger = logging.getLogger(__name__)

ANALYSIS_PROMPT = """You are a cybersecurity analyst AI. Analyze the following log entries for potential security threats.

For each threat detected, respond ONLY with a JSON array. Each item should have:
- "event_type": one of "BRUTE_FORCE", "SQL_INJECTION", "PRIVILEGE_ESCALATION", "ANOMALY"
- "severity": one of "LOW", "MEDIUM", "HIGH", "CRITICAL"
- "description": brief explanation of the threat
- "confidence": float 0.0 to 1.0

If no threats are detected, respond with an empty array: []

Log entries to analyze:
{logs}
"""


def _format_logs(logs: list[LogMessage]) -> str:
    return "\n".join(
        f"[{log.timestamp}] {log.source} | {log.source_ip} | {log.method} {log.endpoint} | {log.message}"
        for log in logs
    )


def _parse_llm_response(response_text: str) -> list[dict]:
    """Parse JSON from LLM response, handling markdown code blocks."""
    text = response_text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    threats = json.loads(text)

    results = []
    for threat in threats:
        results.append({
            "event_type": threat.get("event_type", EventType.ANOMALY),
            "severity": threat.get("severity", Severity.MEDIUM),
            "description": threat.get("description", "AI-detected anomaly"),
            "confidence": threat.get("confidence", 0.5),
            "detected_by": "AI",
        })
    return results


async def _analyze_with_openai(logs_text: str) -> list[dict]:
    """Call OpenAI API (GPT-4o mini etc.)."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
            json={
                "model": settings.OPENAI_MODEL,
                "messages": [
                    {"role": "user", "content": ANALYSIS_PROMPT.format(logs=logs_text)}
                ],
                "max_tokens": 1024,
                "temperature": 0.1,
            },
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return _parse_llm_response(content)


async def _analyze_with_claude(logs_text: str) -> list[dict]:
    """Call Claude API."""
    client = anthropic.Anthropic(api_key=settings.CLAUDE_API_KEY)
    message = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=1024,
        messages=[
            {"role": "user", "content": ANALYSIS_PROMPT.format(logs=logs_text)}
        ],
    )
    return _parse_llm_response(message.content[0].text)


async def _analyze_with_ollama(logs_text: str) -> list[dict]:
    """Call local LLM via OpenAI-compatible API (llama-server / Ollama)."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        # Try OpenAI-compatible endpoint first (llama-server, vLLM, etc.)
        response = await client.post(
            f"{settings.OLLAMA_HOST}/v1/chat/completions",
            json={
                "model": settings.OLLAMA_MODEL,
                "messages": [
                    {"role": "user", "content": ANALYSIS_PROMPT.format(logs=logs_text)}
                ],
                "max_tokens": 1024,
                "temperature": 0.1,
            },
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return _parse_llm_response(content)


async def analyze_with_llm(logs: list[LogMessage]) -> list[dict]:
    """Route to the configured LLM provider."""
    provider = settings.LLM_PROVIDER.lower()

    if provider == "none":
        logger.debug("LLM provider set to 'none', skipping AI analysis")
        return []

    if provider == "openai" and not settings.OPENAI_API_KEY:
        logger.warning("OpenAI selected but API key not set, skipping")
        return []
    if provider == "claude" and not settings.CLAUDE_API_KEY:
        logger.warning("Claude selected but API key not set, skipping")
        return []

    try:
        logs_text = _format_logs(logs)

        if provider == "openai":
            results = await _analyze_with_openai(logs_text)
        elif provider == "claude":
            results = await _analyze_with_claude(logs_text)
        elif provider == "ollama":
            results = await _analyze_with_ollama(logs_text)
        else:
            logger.error(f"Unknown LLM provider: {provider}")
            return []

        logger.info(f"LLM ({provider}) found {len(results)} threats in {len(logs)} logs")
        return results

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse LLM response: {e}")
        return []
    except Exception as e:
        logger.error(f"LLM analysis failed ({provider}): {e}")
        return []
