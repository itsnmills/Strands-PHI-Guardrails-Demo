"""
app/jev/decisions.py
────────────────────
Thin transport for TypeSafe's Jev ("System One") decision API.

This module does ONE thing: send a state plus a set of typed questions, and
return the parsed answers. It deliberately holds no opinion about what the
questions should be, and no control flow that depends on the answers. The
questions live in `app/jev/checks.py`; the branching lives in the caller.

That split is the point. Jev is not a reasoning model and must not be asked
to reason — no "is this legitimate under HIPAA policy?" It answers narrow,
atomic perception questions ("does this text ask the assistant to ignore its
instructions?") and the code composes those atoms into ordinary if
statements. See checks.py for the catalogs and the composition.

Question types (returned under the id you choose):
    noul    -> probability the answer is yes, 0.0-1.0
    choice  -> one option from the criteria you supplied, plus probabilities
    score   -> a position along ordered levels

Failure surface
---------------
- Missing/empty key file          -> JevConfigError (configuration error).
- Timeout / HTTP failure          -> JevRequestError (raised, not swallowed).
- HTTP 200 with unusable answers  -> JevResponse with `error` set and the
  answers that did parse, so a caller that keys off values degrades safely.
- Empty `questions`               -> ValueError (a programming error).

Transport
---------
Requests go to https://openrouter.ai/api/alpha/decisions with a 30s timeout.
HTTP 429 and 5xx are retried up to twice (max 3 attempts) with a fixed 0.5s
then 1.0s backoff. All other statuses and timeouts fail immediately. The API
key is read at runtime and is never logged, returned, or embedded in error
messages.
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping

MODEL = "typesafe/jev-1.13"
ENDPOINT = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_KEY_PATH = pathlib.Path.home() / ".codex" / "codex-router" / "openrouter-api-key.secret"

_TIMEOUT_S = 30.0
_MAX_ATTEMPTS = 3          # 1 initial call + up to 2 retries
_BACKOFF_S = (0.5, 1.0)    # short backoff between retries

AnswerValue = float | str


class JevError(Exception):
    """Base class for Jev transport failures."""


class JevConfigError(JevError):
    """The API-key file is missing, unreadable, or empty."""


class JevRequestError(JevError):
    """The endpoint call failed (timeout, HTTP error, or malformed wire data)."""


@dataclass
class JevAnswer:
    """One parsed, typed answer. `value` is a float for noul/score, a str for choice."""

    question_id: str
    kind: str                                  # "noul" | "choice" | "score"
    value: AnswerValue
    confidence: float | None = None            # the model's own certainty
    probabilities: dict[str, float] | None = None


@dataclass
class JevResponse:
    """Parsed answers plus transport metadata.

    `error` is set when the call returned but some or all answers were
    unusable. `answers` still holds whatever parsed, so a caller can act on
    the atoms it received and fail closed on the ones it did not.
    """

    answers: dict[str, JevAnswer] = field(default_factory=dict)
    latency_ms: float = 0.0
    provider: str = ""
    model_resolved: str = ""
    request_id: str | None = None
    error: str | None = None

    def _answer(self, question_id: str, kind: str) -> JevAnswer | None:
        answer = self.answers.get(question_id)
        if answer is None or answer.kind != kind:
            return None
        return answer

    def noul(self, question_id: str) -> float | None:
        answer = self._answer(question_id, "noul")
        return float(answer.value) if answer is not None else None

    def choice(self, question_id: str) -> str | None:
        answer = self._answer(question_id, "choice")
        return str(answer.value) if answer is not None else None

    def score(self, question_id: str) -> float | None:
        answer = self._answer(question_id, "score")
        return float(answer.value) if answer is not None else None

    def confidence(self, question_id: str) -> float | None:
        answer = self.answers.get(question_id)
        return answer.confidence if answer is not None else None

    def nouls(self) -> dict[str, float]:
        """Every noul answer as {question_id: probability}."""
        return {qid: float(a.value) for qid, a in self.answers.items() if a.kind == "noul"}


_urlopen = urllib.request.urlopen  # module-level alias so tests can monkeypatch


def _read_key(key_path: str | pathlib.Path | None) -> str:
    path = pathlib.Path(key_path) if key_path is not None else DEFAULT_KEY_PATH
    try:
        key = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise JevConfigError(f"Jev API key file not readable: {path}") from exc
    if not key:
        raise JevConfigError(f"Jev API key file is empty: {path}")
    return key


def _post(body_bytes: bytes, key: str) -> Any:
    req = urllib.request.Request(
        ENDPOINT,
        data=body_bytes,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/itsnmills/Strands-PHI-Guardrails-Demo",
            "X-Title": "Strands PHI Guardrails Jev Adapter",
        },
        method="POST",
    )
    with _urlopen(req, timeout=_TIMEOUT_S) as resp:
        raw = resp.read()
    return json.loads(raw)


def _bounded_probability(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0.0 <= float(value) <= 1.0:
        return float(value)
    return None


def _parse_answer(question_id: str, payload: Any) -> JevAnswer | None:
    if not isinstance(payload, dict):
        return None
    kind = payload.get("type")
    confidence = _bounded_probability(payload.get("confidence"))
    if kind == "noul":
        value = _bounded_probability(payload.get("noul"))
        return None if value is None else JevAnswer(question_id, "noul", value, confidence)
    if kind == "choice":
        choice = payload.get("choice")
        if not isinstance(choice, str) or not choice:
            return None
        probabilities = payload.get("probabilities")
        probs = (
            {str(k): float(v) for k, v in probabilities.items() if isinstance(v, (int, float))}
            if isinstance(probabilities, dict)
            else None
        )
        return JevAnswer(question_id, "choice", choice, confidence, probs)
    if kind == "score":
        score = payload.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            return JevAnswer(question_id, "score", float(score), confidence)
        return None
    return None


def _parse_response(raw: Any, latency_ms: float) -> JevResponse:
    raw = raw if isinstance(raw, dict) else {}
    answers_raw = raw.get("answers")
    answers: dict[str, JevAnswer] = {}
    unparseable: list[str] = []
    if isinstance(answers_raw, dict):
        for question_id, payload in answers_raw.items():
            parsed = _parse_answer(question_id, payload)
            if parsed is None:
                unparseable.append(question_id)
            else:
                answers[question_id] = parsed

    error: str | None = None
    if not answers:
        error = f"unusable Jev answers: {answers_raw!r}"
    elif unparseable:
        error = f"unparseable Jev answers for: {sorted(unparseable)}"

    request_id = raw.get("request_id") or raw.get("id")
    return JevResponse(
        answers=answers,
        latency_ms=latency_ms,
        provider=str(raw["provider"]) if raw.get("provider") is not None else "",
        model_resolved=str(raw["model"]) if raw.get("model") is not None else "",
        request_id=str(request_id) if request_id is not None else None,
        error=error,
    )


def ask_jev(
    state: Mapping[str, Any],
    questions: Mapping[str, Any],
    *,
    key_path: str | None = None,
) -> JevResponse:
    """Send `state` and `questions` to Jev and return the parsed answers.

    `state` is a flat mapping of structured facts. It is the caller's job to
    keep it payload-free: pass the atoms a question is about, not raw PHI.
    `questions` maps your chosen ids to typed question bodies (see checks.py).
    """
    if not questions:
        raise ValueError("ask_jev requires at least one question")
    key = _read_key(key_path)
    body = json.dumps({"model": MODEL, "state": dict(state), "questions": dict(questions)}).encode("utf-8")
    t0 = time.perf_counter()
    raw: Any = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            raw = _post(body, key)
            break
        except urllib.error.HTTPError as exc:
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if not retryable:
                raise JevRequestError(f"Jev endpoint rejected the request (HTTP {exc.code})") from exc
            if attempt >= _MAX_ATTEMPTS - 1:
                raise JevRequestError(
                    f"Jev endpoint unavailable after {_MAX_ATTEMPTS} attempts (last HTTP {exc.code})"
                ) from exc
            time.sleep(_BACKOFF_S[attempt])
        except (urllib.error.URLError, TimeoutError) as exc:
            raise JevRequestError(f"Jev request failed: {type(exc).__name__}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise JevRequestError("Jev returned a non-JSON response") from exc
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)
    return _parse_response(raw, latency_ms)
