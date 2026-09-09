from __future__ import annotations

import json
from pathlib import Path

from .models import Grant, Principal


def load_inventory(path: str | Path) -> tuple[list[Principal], list[Grant]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    principals = [Principal(**item) for item in payload.get("principals", [])]
    grants = [Grant(**item) for item in payload.get("grants", [])]
    if not principals:
        raise ValueError("inventory must contain at least one principal")
    return principals, grants
