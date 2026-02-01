from __future__ import annotations

from typing import Literal, TypedDict


class ColorPreset(TypedDict):
    high: str
    medium: str
    low: str


COLOR_PRESETS: dict[str, ColorPreset] = {
    "default": {"high": "31", "medium": "33", "low": "36"},
    "vivid": {"high": "91", "medium": "93", "low": "96"},
    "muted": {"high": "31", "medium": "33", "low": "34"},
}


ThemeName = Literal["system", "light", "dark"]

THEME_OVERRIDES: dict[ThemeName, dict[str, str]] = {
    "system": {},
    "light": {
        "--bg": "#f6f7fb",
        "--card": "#ffffff",
        "--text": "#111827",
        "--muted": "#6b7280",
        "--border": "#e5e7eb",
    },
    "dark": {
        "--bg": "#0b0f19",
        "--card": "#111827",
        "--text": "#f9fafb",
        "--muted": "#9ca3af",
        "--border": "#1f2937",
    },
}

