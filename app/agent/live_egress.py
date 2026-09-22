"""Fail-closed policy for the demo's hosted-model egress path."""

from collections.abc import Iterable, Mapping


def is_approved_live_fixture(
    prompt: str,
    scenario_id: str | None,
    scenarios: Iterable[Mapping[str, str]],
) -> bool:
    """Only permit a verbatim built-in synthetic prompt to leave the app."""
    return any(
        scenario.get("id") == scenario_id and scenario.get("prompt") == prompt
        for scenario in scenarios
    )
