from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal


def get_schema(
    kind: Literal["analyze", "diff", "report", "all"] = "all",
) -> Mapping[str, Any]:
    if kind == "analyze":
        return ANALYZE_SCHEMA
    if kind == "diff":
        return DIFF_SCHEMA
    if kind == "report":
        return REPORT_SCHEMA
    return ALL_SCHEMA


DIRECTIVES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": {
        "type": "array",
        "items": {"type": "string"},
    },
}

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "key": {"type": "string"},
        "severity": {"type": "string", "enum": ["high", "medium", "low"]},
        "title": {"type": "string"},
        "detail": {"type": "string"},
        "evidence": {"type": ["string", "null"]},
    },
    "required": ["key", "severity", "title", "detail"],
}

ANALYZE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/csp-doctor/schema/analyze.json",
    "title": "csp-doctor analyze --format json output",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "directives": DIRECTIVES_SCHEMA,
        "findings": {
            "type": "array",
            "items": FINDING_SCHEMA,
        },
    },
    "required": ["directives", "findings"],
}

SEVERITY_CHANGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "key": {"type": "string"},
        "from": {"type": "string", "enum": ["high", "medium", "low"]},
        "to": {"type": "string", "enum": ["high", "medium", "low"]},
        "title": {"type": "string"},
    },
    "required": ["key", "from", "to", "title"],
}

CHANGED_DIRECTIVE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "added": {"type": "array", "items": {"type": "string"}},
        "removed": {"type": "array", "items": {"type": "string"}},
        "before": {"type": "array", "items": {"type": "string"}},
        "after": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["added", "removed", "before", "after"],
}

DIFF_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/csp-doctor/schema/diff.json",
    "title": "csp-doctor diff --format json output",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "baseline_directives": DIRECTIVES_SCHEMA,
        "directives": DIRECTIVES_SCHEMA,
        "added_directives": {"type": "array", "items": {"type": "string"}},
        "removed_directives": {"type": "array", "items": {"type": "string"}},
        "changed_directives": {
            "type": "object",
            "additionalProperties": CHANGED_DIRECTIVE_SCHEMA,
        },
        "added_findings": {"type": "array", "items": FINDING_SCHEMA},
        "removed_findings": {"type": "array", "items": FINDING_SCHEMA},
        "severity_changes": {"type": "array", "items": SEVERITY_CHANGE_SCHEMA},
    },
    "required": [
        "baseline_directives",
        "directives",
        "added_directives",
        "removed_directives",
        "changed_directives",
        "added_findings",
        "removed_findings",
        "severity_changes",
    ],
}

COUNTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "high": {"type": "integer", "minimum": 0},
        "medium": {"type": "integer", "minimum": 0},
        "low": {"type": "integer", "minimum": 0},
    },
    "required": ["high", "medium", "low"],
}

VIOLATION_ORIGIN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "origin": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
    },
    "required": ["origin", "count"],
}

VIOLATION_DIRECTIVE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "directive": {"type": "string"},
        "count": {"type": "integer", "minimum": 0},
        "top_blocked_origins": {"type": "array", "items": VIOLATION_ORIGIN_SCHEMA},
    },
    "required": ["directive", "count", "top_blocked_origins"],
}

VIOLATIONS_SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "file": {"type": "string"},
        "skipped": {"type": "integer", "minimum": 0},
        "total_events": {"type": "integer", "minimum": 0},
        "directives": {"type": "array", "items": VIOLATION_DIRECTIVE_SCHEMA},
    },
    "required": ["file", "skipped", "total_events", "directives"],
}

REPORT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/csp-doctor/schema/report.json",
    "title": "csp-doctor report --format json output",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "policy": {"type": "string"},
        "profile": {"type": "string"},
        "theme": {"type": "string"},
        "template": {"type": "string"},
        "directives": DIRECTIVES_SCHEMA,
        "findings": {"type": "array", "items": FINDING_SCHEMA},
        "counts": COUNTS_SCHEMA,
        "summary": {"type": "string"},
        "violations": VIOLATIONS_SUMMARY_SCHEMA,
    },
    "required": [
        "policy",
        "profile",
        "theme",
        "template",
        "directives",
        "findings",
        "counts",
        "summary",
    ],
}

ALL_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/csp-doctor/schema/all.json",
    "title": "csp-doctor JSON output schemas",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "analyze": ANALYZE_SCHEMA,
        "diff": DIFF_SCHEMA,
        "report": REPORT_SCHEMA,
    },
    "required": ["analyze", "diff", "report"],
}
