from types import SimpleNamespace

from app.agent.live_egress import is_approved_live_fixture
from app.agent.traffic import TrafficRecorder


def test_live_egress_accepts_only_the_exact_selected_fixture():
    scenarios = [{"id": "A1", "prompt": "Synthetic fixture"}]

    assert is_approved_live_fixture("Synthetic fixture", "A1", scenarios)
    assert not is_approved_live_fixture("Synthetic fixture edited", "A1", scenarios)
    assert not is_approved_live_fixture("Synthetic fixture", "B1", scenarios)


def test_traffic_recorder_never_retains_request_or_response_content():
    secret = "SSN 123-45-6789 synthetic patient"
    store = []
    recorder = TrafficRecorder().bind(store)
    rec = recorder._append("model-id", [{"role": "user", "content": secret}], {
        "litellm_call_id": "call-123",
    })
    chunk = SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(
        content=secret, reasoning_content=secret,
    ))])
    recorder._accumulate(chunk)
    recorder._finalize({"litellm_call_id": rec["id"]}, None, None, None)

    assert secret not in repr(rec)
    assert not {"request_messages", "stream_text", "stream_reasoning", "final_text"} & rec.keys()
    assert rec["chunks"] == 1
    assert rec["status"] == "complete"


def test_traffic_recorder_keeps_error_type_without_exception_text():
    secret = "patient SSN 123-45-6789"
    recorder = TrafficRecorder().bind([])
    recorder._failure({"model": "model-id", "exception": RuntimeError(secret)}, None, None)

    assert secret not in repr(recorder.store)
    assert recorder.store[0]["error_type"] == "RuntimeError"
