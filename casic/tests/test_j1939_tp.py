from __future__ import annotations

from pathlib import Path

from casic.core.logging import PacketLogger
from casic.core.models import CANFrame, FuzzConfig
from casic.protocols.j1939 import J1939Fuzzer


def _build_config(tp_probability: float, da: int = 0xFE) -> FuzzConfig:
    return FuzzConfig(
        interface="can0",
        rate_mode=1,
        source_mode="rand",
        destination="rand",
        packet_count=1,
        print_interval=0,
        seed=7,
        j1939_priority=3,
        j1939_pgn=0xFEF2,
        j1939_sa=0x80,
        j1939_da=da,
        j1939_tp_probability=tp_probability,
        j1939_invalid_pgn_probability=0.0,
    )


def _extract_pf(can_id: int) -> int:
    return (can_id >> 16) & 0xFF


def test_j1939_tp_probability_one_generates_cm_and_dt_burst():
    fuzzer = J1939Fuzzer(_build_config(tp_probability=1.0))

    frame = fuzzer.generate_frame(1)

    assert isinstance(frame, CANFrame)
    assert _extract_pf(frame.can_id) == 0xEC
    burst = frame.meta.get("burst", [])
    assert burst
    assert all(_extract_pf(b.can_id) == 0xEB for b in burst)
    assert [b.data[0] for b in burst] == list(range(1, len(burst) + 1))


def test_j1939_tp_probability_zero_generates_regular_single_frame():
    fuzzer = J1939Fuzzer(_build_config(tp_probability=0.0))

    frame = fuzzer.generate_frame(1)

    assert frame.meta.get("burst", []) == []
    assert _extract_pf(frame.can_id) == 0xFE


def test_j1939_global_destination_uses_bam_cm_control():
    fuzzer = J1939Fuzzer(_build_config(tp_probability=1.0, da=0xFF))

    frame = fuzzer.generate_frame(1)

    assert frame.data[0] == 0x20


def test_j1939_tp_anomaly_and_timing_metadata_present():
    cfg = _build_config(tp_probability=1.0)
    cfg.j1939_tp_sequence_anomaly_probability = 1.0
    cfg.j1939_tp_timing_fault_probability = 1.0

    fuzzer = J1939Fuzzer(cfg)
    frame = fuzzer.generate_frame(1)

    assert frame.meta.get("tp_sequence_anomaly") in {"gap", "duplicate", "reorder"}
    assert frame.meta.get("tp_timing_fault_ms") in {25, 50, 100, 250}


def test_j1939_correlation_uses_pgn_and_address_context(tmp_path: Path):
    logger = PacketLogger()
    request_id = (3 << 26) | (0xEA << 16) | (0xFE << 8) | 0x80
    response_id = (3 << 26) | (0xEA << 16) | (0xFE << 8) | 0x80
    logger.record_sent(CANFrame(can_id=request_id, data=b"\x00" * 8, is_extended_id=True, timestamp=1.0))
    logger.record_received(CANFrame(can_id=response_id, data=b"\x01" * 8, is_extended_id=True, timestamp=1.01))

    rows = logger.build_correlation_rows(protocol="j1939", run_id="runj", window_seconds=1.0)

    assert len(rows) == 1
    assert rows[0].match_status == "matched"
    assert rows[0].correlation_key == "pgn:59904|sa:128|da:254"
    assert rows[0].latency_ms == 10.0

    report = tmp_path / "j1939_corr.csv"
    PacketLogger.write_correlation_csv(path=report, protocol="j1939", run_id="runj", rows=rows)
    assert "unmatched_requests" in report.read_text(encoding="utf-8")


def test_metadata_only_correlation_report_for_unsupported_protocol(tmp_path: Path):
    report = tmp_path / "unsupported.csv"
    PacketLogger.write_correlation_csv(
        path=report,
        protocol="cosic",
        run_id="runx",
        rows=[],
        unsupported_reason="Protocol does not support request-response correlation",
    )
    text = report.read_text(encoding="utf-8")
    assert "unsupported_reason" in text
    assert "Protocol does not support request-response correlation" in text
