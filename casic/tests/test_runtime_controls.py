from __future__ import annotations

import pytest

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame, FuzzConfig


class DummyFuzzer(BaseFuzzer):
    protocol_name = "dummy"

    def generate_frame(self, sequence_number: int) -> CANFrame:
        return CANFrame(can_id=0x123, data=b"\x00")


def _build_config(rate_mode: int = 0) -> FuzzConfig:
    return FuzzConfig(
        interface="can0",
        rate_mode=rate_mode,
        source_mode="rand",
        destination="rand",
        packet_count=1,
        print_interval=0,
    )


def test_rate_mode_0_waits_for_send_slot(monkeypatch):
    fuzzer = DummyFuzzer(_build_config(rate_mode=0))
    fuzzer._next_send_ts = 5.0

    calls: list[float] = []

    def fake_sleep(duration: float):
        calls.append(duration)

    monotonic_values = iter([4.6, 5.0])

    monkeypatch.setattr("casic.core.engine.time.sleep", fake_sleep)
    monkeypatch.setattr("casic.core.engine.time.monotonic", lambda: next(monotonic_values))

    fuzzer._wait_for_send_slot()

    assert calls and calls[0] == pytest.approx(0.4)


def test_rate_mode_1_has_no_wait(monkeypatch):
    fuzzer = DummyFuzzer(_build_config(rate_mode=1))

    called = False

    def fail_sleep(_duration: float):
        nonlocal called
        called = True

    monkeypatch.setattr("casic.core.engine.time.sleep", fail_sleep)
    fuzzer._wait_for_send_slot()

    assert called is False
