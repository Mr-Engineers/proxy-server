import json
import logging
import sys
from datetime import datetime, timezone

HANDLER_NAME = "proxy-json-stdout"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        entry.update(getattr(record, "fields", {}))
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: str) -> None:
    root = logging.getLogger()
    root.handlers = [handler for handler in root.handlers if handler.get_name() != HANDLER_NAME]
    handler = logging.StreamHandler(sys.stdout)
    handler.set_name(HANDLER_NAME)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())

    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def render_body(raw: bytes, limit: int) -> object:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    if len(text) > limit:
        return {"truncated": True, "bytes": len(raw), "preview": text[:limit]}
    try:
        return json.loads(text)
    except ValueError:
        return text
