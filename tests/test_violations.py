import json

from csp_doctor.violations import load_violation_events


def test_load_violation_events_supports_wrapped_reports_array(tmp_path) -> None:
    path = tmp_path / "wrapped.json"
    path.write_text(
        json.dumps(
            {
                "reports": [
                    {
                        "body": {
                            "effectiveDirective": "script-src",
                            "blockedURL": "https://cdn.example.com/app.js",
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    events, skipped = load_violation_events(path)

    assert skipped == 0
    assert len(events) == 1
    assert events[0].directive == "script-src"
    assert events[0].blocked_origin == "https://cdn.example.com"


def test_load_violation_events_supports_json_string_bodies(tmp_path) -> None:
    path = tmp_path / "string-bodies.ndjson"
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "body": json.dumps(
                            {
                                "effectiveDirective": "img-src",
                                "blockedURL": "data:image/png;base64,aaaa",
                            }
                        )
                    }
                ),
                json.dumps(
                    {
                        "csp-report": json.dumps(
                            {
                                "effective-directive": "script-src",
                                "blocked-uri": "https://cdn.example.com/app.js",
                            }
                        )
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    events, skipped = load_violation_events(path)

    assert skipped == 0
    assert len(events) == 2
    directives = {event.directive for event in events}
    assert directives == {"img-src", "script-src"}


def test_load_violation_events_counts_non_dict_wrapped_items_as_skipped(tmp_path) -> None:
    path = tmp_path / "wrapped-mixed.json"
    path.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "body": {
                            "effectiveDirective": "style-src",
                            "blockedURL": "https://cdn.example.com/app.css",
                        }
                    },
                    "unexpected",
                    123,
                ]
            }
        ),
        encoding="utf-8",
    )

    events, skipped = load_violation_events(path)

    assert len(events) == 1
    assert skipped == 2
