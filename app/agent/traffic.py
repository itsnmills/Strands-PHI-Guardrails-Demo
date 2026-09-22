"""Payload-free model-call metadata recorder.

Never retain request messages, response text, reasoning, or exception text:
they may contain patient data.
"""

import datetime
import uuid

from litellm.integrations.custom_logger import CustomLogger


def _delta_ms(start, end) -> float | None:
    try:
        return round((end - start).total_seconds() * 1000, 1)
    except Exception:
        return None


class TrafficRecorder(CustomLogger):
    """Appends one record per LLM call to a bound store."""

    def __init__(self):
        super().__init__()
        self.store: list[dict] = []
        self._pending: dict[str, dict] = {}

    # ── Store management ────────────────────────────────────────

    def bind(self, store: list) -> "TrafficRecorder":
        self.store = store
        self._pending = {}
        return self

    def _append(self, model, messages, details: dict) -> dict:
        rec = {
            "id": (details.get("litellm_call_id") or str(uuid.uuid4()))[:8],
            "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S"),
            "model": str(model)[:100],
            "status": "requesting",
            "request_params": {
                k: details.get(k) for k in ("temperature", "max_tokens", "stream", "num_retries")
                if details.get(k) is not None
            },
            "chunks": 0,
            "usage": None,
            "latency_ms": None,
            "error_type": None,
        }
        self.store.append(rec)
        self._pending[rec["id"]] = rec
        return rec

    def _rec_for(self, details: dict | None) -> dict | None:
        if not details:
            return None
        call_id = details.get("litellm_call_id")
        if call_id and call_id in self._pending:
            return self._pending[call_id]
        pending = [r for r in self.store if r["status"] == "requesting"]
        return pending[-1] if pending else None

    def _accumulate(self, chunk) -> None:
        rec = self._current
        if rec is None:
            return
        try:
            rec["chunks"] += 1
            rec["status"] = "streaming"
        except Exception:
            pass

    @property
    def _current(self) -> dict | None:
        """The record currently awaiting stream data (single-flight in this demo)."""
        pending = [r for r in self.store if r["status"] == "requesting"]
        if self._pending:
            return self._pending.get(list(self._pending.values())[0]["id"])
        return pending[-1] if pending else None

    def _finalize(self, details: dict, response_obj, start, end, failed: bool = False) -> None:
        rec = self._rec_for(details)
        if rec is None:
            return
        usage = details.get("response_usage") or getattr(response_obj, "usage", None)
        if usage is not None:
            rec["usage"] = {
                "prompt": getattr(usage, "prompt_tokens", None),
                "completion": getattr(usage, "completion_tokens", None),
                "total": getattr(usage, "total_tokens", None),
            }
        rec["latency_ms"] = _delta_ms(start, end)
        if failed:
            rec["status"] = "error"
            exc = details.get("exception") or details.get("original_exception")
            rec["error_type"] = type(exc).__name__ if exc else "RequestFailed"
        else:
            rec["status"] = "complete"
        self._pending.pop(rec["id"], None)
        if len(self.store) > 40:
            del self.store[:len(self.store) - 40]

    # ── Hooks (signatures per litellm's Logging.async_success_handler) ──

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Strip reasoning fields from replayed assistant messages — Go rejects
        `reasoningContent` on multi-turn Chat Completions calls."""
        for msg in data.get("messages", []) or []:
            if isinstance(msg, dict):
                for field in ("reasoning_content", "reasoning", "reasoningContent"):
                    msg.pop(field, None)
        return data

    async def async_log_pre_api_call(self, model, messages, kwargs):
        self._append(model, messages, kwargs)

    async def async_log_stream_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._accumulate(response_obj)

    async def async_log_success_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._finalize(kwargs, response_obj, start_time, end_time)

    async def async_log_failure_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._failure(kwargs, start_time, end_time)

    def log_pre_api_call(self, model, messages, kwargs):
        self._append(model, messages, kwargs)

    def log_stream_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._accumulate(response_obj)

    def log_success_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._finalize(kwargs, response_obj, start_time, end_time)

    def log_failure_event(self, kwargs=None, response_obj=None, start_time=None, end_time=None, **_):
        self._failure(kwargs, start_time, end_time)

    def _failure(self, details: dict, start, end) -> None:
        rec = self._rec_for(details)
        if rec is None:
            rec = self._append(details.get("model", "?"), [], details)
        rec["status"] = "error"
        exc = details.get("exception") or details.get("original_exception")
        rec["error_type"] = type(exc).__name__ if exc else "RequestFailed"
        rec["latency_ms"] = _delta_ms(start, end)
        self._pending.pop(rec["id"], None)
        if len(self.store) > 40:
            del self.store[:len(self.store) - 40]


TRAFFIC = TrafficRecorder()
