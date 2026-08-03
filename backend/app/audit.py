from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .storage import APP_DATA, read_json, write_json

AUDIT_FILE = APP_DATA / "audit.jsonl"


def record(action: str, details: dict[str, Any]) -> None:
    entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": action, "details": details}
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_FILE.open("a", encoding="utf-8") as handle:
        handle.write(__import__("json").dumps(entry, ensure_ascii=False) + "\n")


def list_records(limit: int = 100) -> list[dict[str, Any]]:
    if not AUDIT_FILE.exists():
        return []
    lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-limit:]
    return [__import__("json").loads(line) for line in lines]
