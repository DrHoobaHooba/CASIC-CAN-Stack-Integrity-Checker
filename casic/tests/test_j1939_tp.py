from __future__ import annotations

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
