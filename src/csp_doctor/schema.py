from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal


def get_schema(kind: Literal["analyze", "diff", "all"] = "all") -> Mapping[str, Any]:
    if kind == "analyze":
        return ANALYZE_SCHEMA
    if kind == "diff":
        return DIFF_SCHEMA
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

ALL_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.invalid/csp-doctor/schema/all.json",
    "title": "csp-doctor JSON output schemas",
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "analyze": ANALYZE_SCHEMA,
        "diff": DIFF_SCHEMA,
    },
    "required": ["analyze", "diff"],
}

