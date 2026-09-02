"""In-Memory Live Telemetry Ring Buffer for APIx."""

import logging
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("apix.telemetry")

# Live In-Memory Telemetry Ring Buffer (bounded to last 100 events)
_TELEMETRY_LOGS: deque[dict[str, Any]] = deque(maxlen=100)


def emit_telemetry(event_type: str, text: str, level: str = "ok"):
    """Append a live event to the in-memory telemetry ring buffer."""
    event = {
        "id": str(uuid.uuid4())[:8],
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type.upper(),
        "text": text,
        "level": level,  # "ok", "info", "warn", "error"
    }
    _TELEMETRY_LOGS.append(event)
    logger.debug("Telemetry [%s]: %s", event["type"], text)


def get_live_telemetry_logs(limit: int = 30) -> list[dict[str, Any]]:
    """Retrieve recent live telemetry log items."""
    logs = list(_TELEMETRY_LOGS)
    return logs[-limit:] if limit > 0 else logs


def clear_telemetry_logs():
    """Clear all in-memory telemetry logs and emit a fresh ready event."""
    _TELEMETRY_LOGS.clear()
    emit_telemetry(
        "READY",
        "Live ingestion telemetry stream cleared by analyst operator.",
        "info",
    )


# Pre-populate initial system start events
emit_telemetry(
    "INIT",
    "APIx Automated Ingestion Engine initialized (Playwright 3-slot pool active)",
    "info",
)
emit_telemetry(
    "ROBOTS", "Robots.txt compliance engine active with async domain cache", "ok"
)
