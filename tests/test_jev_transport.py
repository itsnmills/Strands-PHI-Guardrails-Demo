"""
tests/test_jev_transport.py
───────────────────────────
Transport tests for app/jev/decisions.py. urllib is fully monkeypatched:
no network is used and no real text is ever involved. Every string here is
synthetic.

The transport holds no opinion about the questions — it sends whatever it
is given and parses typed answers back. Question design lives in checks.py
and is tested there.
"""

from __future__ import annotations

import io
import json
import types
import urllib.error

import pytest

import app.jev.decisions as decisions
from app.jev.decisions import (
    JevConfigError,
    JevRequestError,
    JevResponse,
    ask_jev,
)

QUESTIONS = {
    "is_urgent": {"type": "noul", "instructions": "Does this express urgency?"},
    "team": {"type": "choice", "instructions": "Which team?", "criteria": {"a": "A", "b": "B"}},
    "severity": {"type": "score", "instructions": "How severe?", "criteria": ["low", "high"]},
}

HAPPY_RESPONSE = {
    "model": "jev-1.13",
    "answers": {
        "is_urgent": {"type": "noul", "noul": 0.92, "confidence": 0.88},
        "team": {"type": "choice", "choice": "b", "confidence": 0.71,
                 "probabilities": {"a": 0.29, "b": 0.71}},
        "severity": {"type": "score", "score": 1.2, "confidence": 0.5},
    },
    "provider": "TypeSafe",
    "request_id": "req-123",
}


@pytest.fixture
def key_file(tmp_path) -> str:
    path = tmp_path / "openrouter-api-key.secret"
    path.write_text("  sk-test-synthetic-key\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def fake_time(monkeypatch):
    """Replace this module's `time` so backoff is instant and observable."""
    backoff_calls: list[float] = []
    fake = types.SimpleNamespace(
        sleep=lambda seconds: backoff_calls.append(seconds),
        perf_counter=lambda: 0.42,
    )
    monkeypatch.setattr(decisions, "time", fake)
    return types.SimpleNamespace(backoff_calls=backoff_calls)


class Transport:
    """Fake urlopen: `wanted` maps 1-based call counts to a JSON dict or exception."""

    def __init__(self, monkeypatch, wanted, raise_on_each=None):
        self.wanted = wanted
        self.raise_on_each = raise_on_each
        self.requests: list[object] = []
        self.timeouts: list[float | None] = []
        monkeypatch.setattr(decisions, "_urlopen", self)

    def __call__(self, req, timeout=None):
        n = len(self.requests) + 1
        self.requests.append(req)
        self.timeouts.append(timeout)
        thing = self.wanted.get(n, self.raise_on_each)
        if isinstance(thing, BaseException):
            raise thing
        if self.raise_on_each is not None:
            raise self.raise_on_each
        return self.wanted[n]


def _json_stream(payload: dict) -> io.BytesIO:
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


def _http_error(status: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        decisions.ENDPOINT, status, "HTTP Error", {}, io.BytesIO(b'{"error":"nope"}')
    )


def test_happy_path_parses_typed_answers(key_file, fake_time, monkeypatch):
    transport = Transport(monkeypatch, {1: _json_stream(HAPPY_RESPONSE)})

    response = ask_jev({"message": "synthetic"}, QUESTIONS, key_path=key_file)

    assert isinstance(response, JevResponse)
    assert response.noul("is_urgent") == pytest.approx(0.92)
    assert response.choice("team") == "b"
    assert response.score("severity") == pytest.approx(1.2)
    assert response.confidence("is_urgent") == pytest.approx(0.88)
    assert response.answers["team"].probabilities == {"a": 0.29, "b": 0.71}
    assert response.provider == "TypeSafe"
    assert response.model_resolved == "jev-1.13"
    assert response.request_id == "req-123"
    assert response.error is None
    assert response.nouls() == {"is_urgent": pytest.approx(0.92)}

    req = transport.requests[0]
    assert req.get_header("Authorization").startswith("Bearer ")
    assert transport.timeouts == [30]          # the 30s contract
    outbound = json.loads(req.data.decode("utf-8"))
    assert outbound["model"] == decisions.MODEL
    assert outbound["state"] == {"message": "synthetic"}
    assert outbound["questions"] == QUESTIONS


def test_wrong_type_lookup_returns_none(key_file, fake_time, monkeypatch):
    Transport(monkeypatch, {1: _json_stream(HAPPY_RESPONSE)})

    response = ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert response.noul("team") is None       # team is a choice, not a noul
    assert response.choice("is_urgent") is None
    assert response.confidence("missing") is None


def test_http_timeout_raises_and_does_not_retry(key_file, fake_time, monkeypatch):
    transport = Transport(monkeypatch, {}, raise_on_each=TimeoutError("timed out"))

    with pytest.raises(JevRequestError, match="timed out"):
        ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert len(transport.requests) == 1


def test_http_400_is_not_retried(key_file, fake_time, monkeypatch):
    transport = Transport(monkeypatch, {}, raise_on_each=_http_error(400))

    with pytest.raises(JevRequestError, match="HTTP 400"):
        ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert len(transport.requests) == 1


def test_http_429_retries_then_succeeds(key_file, fake_time, monkeypatch):
    transport = Transport(
        monkeypatch,
        {1: _http_error(429), 2: _http_error(429), 3: _json_stream(HAPPY_RESPONSE)},
    )

    response = ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert response.error is None
    assert response.noul("is_urgent") == pytest.approx(0.92)
    assert len(transport.requests) == 3            # initial + exactly 2 retries
    assert fake_time.backoff_calls == [0.5, 1.0]


def test_missing_key_file_raises_before_any_request(tmp_path, monkeypatch):
    transport = Transport(monkeypatch, {})

    with pytest.raises(JevConfigError, match="not readable"):
        ask_jev({"x": 1}, QUESTIONS, key_path=str(tmp_path / "definitely-missing.key"))

    assert transport.requests == []


def test_empty_key_file_raises_before_any_request(tmp_path):
    empty = tmp_path / "empty.key"
    empty.write_text("\n", encoding="utf-8")

    with pytest.raises(JevConfigError, match="empty"):
        ask_jev({"x": 1}, QUESTIONS, key_path=str(empty))


def test_empty_questions_is_a_programming_error(key_file):
    with pytest.raises(ValueError, match="at least one question"):
        ask_jev({"x": 1}, {}, key_path=key_file)


def test_unusable_200_sets_error_and_no_answers(key_file, fake_time, monkeypatch):
    Transport(monkeypatch, {1: _json_stream({"model": "jev-1.13", "answers": {}, "provider": "TypeSafe"})})

    response = ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert response.error is not None
    assert "unusable" in response.error
    assert response.answers == {}
    assert response.noul("is_urgent") is None


def test_partial_unusable_keeps_what_parsed(key_file, fake_time, monkeypatch):
    Transport(monkeypatch, {1: _json_stream({
        "model": "jev-1.13",
        "answers": {"is_urgent": {"type": "noul", "noul": 0.4}, "team": {"type": "choice"}},
        "provider": "TypeSafe",
    })})

    response = ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert response.noul("is_urgent") == pytest.approx(0.4)   # kept
    assert response.answers.get("team") is None               # malformed, dropped
    assert response.error is not None and "team" in response.error


def test_out_of_range_probability_is_rejected(key_file, fake_time, monkeypatch):
    Transport(monkeypatch, {1: _json_stream({
        "model": "jev-1.13",
        "answers": {"is_urgent": {"type": "noul", "noul": 1.4}},
    })})

    response = ask_jev({"x": 1}, QUESTIONS, key_path=key_file)

    assert response.answers == {}
    assert response.error is not None
