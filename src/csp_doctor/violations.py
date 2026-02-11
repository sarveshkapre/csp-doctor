from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(frozen=True)
class ViolationEvent:
    directive: str
    blocked_uri: str
    blocked_origin: str
    disposition: str | None = None


def _read_json_or_ndjson(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read a JSON file that may be a list/object, or newline-delimited JSON.

    Returns (records, skipped_count).
    """
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return [], 0

    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        skipped = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if isinstance(item, dict):
                records.append(item)
            else:
                skipped += 1
        return records, skipped

    if isinstance(loaded, list):
        loaded_records: list[dict[str, Any]] = []
        skipped = 0
        for item in loaded:
            if isinstance(item, dict):
                loaded_records.append(item)
            else:
                skipped += 1
        return loaded_records, skipped
    if isinstance(loaded, dict):
        for key in ("reports", "violations", "events"):
            wrapped = loaded.get(key)
            if isinstance(wrapped, list):
                wrapped_records = [item for item in wrapped if isinstance(item, dict)]
                skipped = len(wrapped) - len(wrapped_records)
                return wrapped_records, skipped
        return [loaded], 0
    return [], 1


def _first_str(mapping: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalize_directive(raw: str) -> str:
    # Reports can include "script-src-elem" etc; keep as-is but lower for grouping.
    return raw.strip().lower()


def _blocked_origin(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return ""

    lowered = stripped.lower()
    if lowered in {"inline", "eval", "self", "none"}:
        return lowered
    if lowered.startswith(("data:", "blob:", "filesystem:", "about:", "chrome-extension:")):
        scheme = lowered.split(":", 1)[0]
        return f"{scheme}:"

    parsed = urlparse(stripped)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    # Some user agents emit just a host or special token; keep a stable label.
    return stripped


def _extract_event(obj: dict[str, Any]) -> ViolationEvent | None:
    body: dict[str, Any] | None = None

    # Legacy report-uri format: {"csp-report": {...}}
    legacy = _parse_embedded_dict(obj.get("csp-report"))
    if legacy is not None:
        body = legacy

    # Reporting API format: {"type":"csp-violation","body":{...}}
    if body is None:
        body = _parse_embedded_dict(obj.get("body"))

    if body is None:
        body = obj

    directive = _first_str(
        body,
        "effectiveDirective",
        "effective-directive",
        "violatedDirective",
        "violated-directive",
    )
    blocked = _first_str(
        body,
        "blockedURL",
        "blocked-uri",
        "blockedURI",
        "blockedUrl",
    )
    if not directive or not blocked:
        return None

    disposition = _first_str(body, "disposition")
    directive_norm = _normalize_directive(directive.split(";", 1)[0])
    return ViolationEvent(
        directive=directive_norm,
        blocked_uri=blocked,
        blocked_origin=_blocked_origin(blocked),
        disposition=disposition.lower() if disposition else None,
    )


def _parse_embedded_dict(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(loaded, dict):
        return loaded
    return None


def load_violation_events(path: Path) -> tuple[list[ViolationEvent], int]:
    records, skipped = _read_json_or_ndjson(path)
    events: list[ViolationEvent] = []
    for record in records:
        event = _extract_event(record)
        if event is None:
            skipped += 1
            continue
        events.append(event)
    return events, skipped


def summarize_violation_events(
    events: list[ViolationEvent],
    *,
    top_directives: int = 10,
    top_origins_per_directive: int = 5,
) -> dict[str, Any]:
    by_directive = Counter(event.directive for event in events if event.directive)

    by_directive_origins: dict[str, Counter[str]] = defaultdict(Counter)
    for event in events:
        if not event.directive or not event.blocked_origin:
            continue
        by_directive_origins[event.directive][event.blocked_origin] += 1

    directives_rendered: list[dict[str, Any]] = []
    for directive, count in by_directive.most_common(top_directives):
        origins = [
            {"origin": origin, "count": count}
            for origin, count in by_directive_origins[directive].most_common(
                top_origins_per_directive
            )
        ]
        directives_rendered.append(
            {
                "directive": directive,
                "count": count,
                "top_blocked_origins": origins,
            }
        )

    return {
        "total_events": len(events),
        "directives": directives_rendered,
    }
