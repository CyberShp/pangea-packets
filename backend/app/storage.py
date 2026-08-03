from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
APP_DATA = ROOT / "app-data"
SCENARIOS_DIR = APP_DATA / "scenarios"
TEMPLATES_DIR = APP_DATA / "templates"
HOSTS_FILE = APP_DATA / "hosts" / "hosts.json"
EXECUTIONS_DIR = APP_DATA / "executions"
EXPORTS_DIR = APP_DATA / "exports"
FILES_DIR = APP_DATA / "files"


def ensure_dirs() -> None:
    for path in [SCENARIOS_DIR, TEMPLATES_DIR / "builtin", TEMPLATES_DIR / "user", HOSTS_FILE.parent, EXECUTIONS_DIR, EXPORTS_DIR, FILES_DIR]:
        path.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
