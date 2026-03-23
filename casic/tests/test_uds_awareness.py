from __future__ import annotations

from pathlib import Path

from casic.core.logging import PacketLogger
from casic.core.models import CANFrame, FuzzConfig
from casic.protocols.uds import UDSFuzzer


def _build_config() -> FuzzConfig:
    return FuzzConfig(
        interface="can0",
        rate_mode=1,
        source_mode="rand",
        destination="0x7E0",
        packet_count=1,
        print_interval=0,
        seed=123,
        uds_request_id=0x7E0,
        uds_max_payload_len=1,
        uds_sequence_awareness_probability=1.0,
        uds_negative_response_awareness_probability=0.0,
        uds_invalid_sid_probability=0.0,
    )


def _decode_single_frame_app_payload(frame: CANFrame) -> bytes:
    payload_len = frame.data[0] & 0x0F
    return frame.data[1 : 1 + payload_len]


def test_sequence_awareness_starts_with_session_control_request():
    fuzzer = UDSFuzzer(_build_config())

    frame = fuzzer.generate_frame(1)
    payload = _decode_single_frame_app_payload(frame)

    assert payload
    assert payload[0] == 0x10


def test_negative_response_awareness_biases_security_followup():
    cfg = _build_config()
    cfg.uds_sequence_awareness_probability = 0.0
    cfg.uds_negative_response_awareness_probability = 1.0

    fuzzer = UDSFuzzer(cfg)
    fuzzer.on_response(CANFrame(can_id=0x7E8, data=bytes([0x03, 0x7F, 0x27, 0x33, 0, 0, 0, 0])))

    frame = fuzzer.generate_frame(1)
    payload = _decode_single_frame_app_payload(frame)

    assert payload
    assert payload[0] == 0x27


def test_security_seed_response_triggers_key_followup_subfunction():
    fuzzer = UDSFuzzer(_build_config())
    fuzzer.on_response(CANFrame(can_id=0x7E8, data=bytes([0x03, 0x67, 0x01, 0xAA, 0, 0, 0, 0])))

    frame = fuzzer.generate_frame(1)
    payload = _decode_single_frame_app_payload(frame)

    assert payload
    assert payload[0] == 0x27
    assert payload[1] == 0x02


def test_uds_correlation_uses_service_context_and_writes_summary_metrics(tmp_path: Path):
    logger = PacketLogger()
    logger.record_sent(CANFrame(can_id=0x7E0, data=bytes([0x02, 0x10, 0x01, 0, 0, 0, 0, 0]), timestamp=10.0))
    logger.record_received(CANFrame(can_id=0x7E8, data=bytes([0x02, 0x50, 0x01, 0, 0, 0, 0, 0]), timestamp=10.02))

    rows = logger.build_correlation_rows(protocol="uds", run_id="run123", window_seconds=1.0)

    assert len(rows) == 1
    assert rows[0].match_status == "matched"
    assert rows[0].correlation_key.startswith("service:16")
    assert rows[0].latency_ms == 20.0

    report = tmp_path / "uds_corr.csv"
    PacketLogger.write_correlation_csv(path=report, protocol="uds", run_id="run123", rows=rows)
    text = report.read_text(encoding="utf-8")
    assert "match_rate_percent" in text
    assert "latency_p50_ms" in text
