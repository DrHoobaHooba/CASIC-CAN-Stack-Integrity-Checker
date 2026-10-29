from collections import Counter
from pathlib import Path

import pytest

from casic.cli.config_runner import _build_common
from casic.cli.yaml_config import load_yaml
from casic.core.parser import CANopenDictionaryParser
from casic.core.transport import socketcan
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer, UDSFuzzer


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "casic" / "examples" / "casic-indepth.yaml"


@pytest.fixture
def profile(monkeypatch):
    monkeypatch.setattr(socketcan, "can", None)
    return load_yaml(PROFILE)


def build(profile, name):
    return _build_common(name, profile["global"], profile["protocols"][name])


def test_indepth_retains_campaign_size_and_capture(profile):
    paths = []
    for name in profile["protocols"]:
        config = build(profile, name)
        assert config.packet_count == 1000000
        assert config.save_responses
        assert config.response_drain_seconds >= 2
        paths.append(config.responses_file)
    assert len(set(paths)) == 4
    assert build(profile, "cansic").raw_feedback_probability == 0.25
    assert build(profile, "cosic").canopen_feedback_probability == 0.35
    assert build(profile, "j1939sic").j1939_feedback_probability == 0.35


def test_indepth_raw_generates_transmittable_classic_frames(profile):
    section = profile["protocols"]["cansic"]
    fuzzer = RawCANFuzzer(build(profile, "cansic"), can_fd=section["can_fd"],
                         mutation_mode=section["mutation"])
    frames = [fuzzer.generate_frame(i) for i in range(2048)]
    assert all(not frame.is_fd and len(frame.data) <= 8 for frame in frames)
    assert {frame.is_extended_id for frame in frames} == {False, True}
    assert len({len(frame.data) for frame in frames}) >= 8
    assert all("error_frame_requested" not in frame.meta for frame in frames)


def test_indepth_uds_exercises_single_and_multi_frame_paths(profile):
    fuzzer = UDSFuzzer(build(profile, "udsic"))
    frames = [fuzzer.generate_frame(i) for i in range(2048)]
    single = [frame for frame in frames if not frame.meta.get("burst")]
    multi = [frame for frame in frames if frame.meta.get("burst")]
    assert 0.15 <= len(single) / len(frames) <= 0.35
    assert len(multi) / len(frames) >= 0.6
    assert len({frame.data[1] for frame in single}) >= 30
    assert any(frame.meta.get("uds_length_mismatch") == "single-frame" for frame in single)
    assert any(frame.meta.get("uds_length_mismatch") == "first-frame" for frame in multi)
    assert any(frame.meta.get("uds_cf_sequence_anomaly") for frame in multi)
    assert all(len(item.data) <= 8 and not item.is_fd
               for frame in frames for item in [frame, *frame.meta.get("burst", [])])


def test_indepth_j1939_exercises_priority_pgn_and_tp_variants(profile):
    fuzzer = J1939Fuzzer(build(profile, "j1939sic"))
    frames = [fuzzer.generate_frame(i) for i in range(2048)]
    assert {frame.can_id >> 26 for frame in frames} == set(range(8))
    assert len({(frame.can_id >> 8) & 0x3FFFF for frame in frames}) > 100
    tp = [frame for frame in frames if "tp_sequence_anomaly" in frame.meta]
    assert 0.4 <= len(tp) / len(frames) <= 0.6
    controls = {
        item.data[0]
        for frame in tp for item in [frame, *frame.meta.get("burst", [])]
        if (item.can_id >> 16) & 0xFF == 0xEC
    }
    assert controls == {0x10, 0x20}
    for key in ("tp_sequence_anomaly", "tp_incomplete_dt", "tp_packet_count_mismatch",
                "tp_cm_dt_order_fault", "tp_timing_fault_ms"):
        assert any(frame.meta.get(key) for frame in tp)


def test_indepth_canopen_exercises_families_and_sdo_modes(profile):
    section = profile["protocols"]["cosic"]
    dictionary = CANopenDictionaryParser().load(ROOT / section["eds"])
    fuzzer = CANopenFuzzer(build(profile, "cosic"), dictionary)
    frames = [fuzzer.generate_frame(i) for i in range(2048)]
    counts = Counter(frame.can_id for frame in frames)
    assert {0, 0x80, 0x100, 0xE1, 0x1E1, 0x661} <= counts.keys()
    sdo = [frame for frame in frames if frame.can_id == 0x661]
    assert any(frame.data[0] == 0x40 for frame in sdo)
    assert any(frame.meta.get("canopen_transfer") == "segmented" for frame in sdo)
    assert any(frame.data[0] == 0x2B for frame in sdo)
    assert any(frame.data[3] in {0x7F, 0x80, 0xFF} for frame in sdo)
