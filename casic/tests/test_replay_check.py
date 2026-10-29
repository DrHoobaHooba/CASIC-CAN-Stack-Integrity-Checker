import json
from pathlib import Path

from casic.cli.replay_check import check_replay, main


def _record(**frame_overrides):
    frame = {
        "can_id": 0x123,
        "data": "010203",
        "is_extended_id": False,
        "is_fd": False,
        "timestamp": 1.0,
        "meta": {},
    }
    frame.update(frame_overrides)
    return {"protocol": "cansic", "frame": frame, "run_id": "run-1", "seed": 1}


def test_replay_check_accepts_current_and_legacy_records(tmp_path: Path):
    path = tmp_path / "capture.jsonl"
    records = [_record(), {"protocol": "cansic", "frame": {"can_id": 0x321, "data": "AABB"}}]
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")

    report = check_replay(path)

    assert report["valid"] is True
    assert report["record_count"] == 2
    assert report["errors"] == 0


def test_replay_check_reports_invalid_ids_and_payloads(tmp_path: Path):
    path = tmp_path / "invalid.jsonl"
    path.write_text(
        json.dumps(_record(can_id=0x800, data="00" * 9)) + "\n",
        encoding="utf-8",
    )

    report = check_replay(path)

    assert report["valid"] is False
    assert report["errors"] == 2


def test_replay_check_warns_about_timestamp_order_and_nonstandard_fd_dlc(tmp_path: Path):
    path = tmp_path / "ordered.jsonl"
    first = _record(timestamp=2.0, is_fd=True, data="00" * 9)
    second = _record(timestamp=1.0, is_fd=True, data="00" * 9)
    path.write_text(f"{json.dumps(first)}\n{json.dumps(second)}\n", encoding="utf-8")

    report = check_replay(path)

    assert report["valid"] is True
    assert report["warnings"] == 3
    assert any("earlier than the previous" in item["message"] for item in report["issues"])


def test_replay_check_reports_line_level_json_errors(tmp_path: Path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"protocol":"cansic"}\n{broken}\n', encoding="utf-8")

    report = check_replay(path)

    assert report["valid"] is False
    assert report["record_count"] == 0
    assert report["errors"] == 2


def test_replay_check_cli_returns_nonzero_for_invalid_file(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    report_path = tmp_path / "report.json"
    path.write_text("", encoding="utf-8")

    result = main([str(path), "--output", str(report_path)])

    assert result == 1
    assert json.loads(report_path.read_text(encoding="utf-8"))["valid"] is False


def test_replay_check_reports_stateful_protocol_context_without_claiming_reconstruction(tmp_path: Path):
    path = tmp_path / "stateful.jsonl"
    uds_request = _record(can_id=0x7E0, data="0210010000000000")
    uds_request["protocol"] = "uds"
    canopen_nmt = _record(can_id=0, data="010A")
    canopen_nmt["protocol"] = "cosic"
    j1939_tp_cm = _record(
        can_id=(3 << 26) | (0xEC << 16) | (0xFE << 8) | 0x80,
        data="2009000200f2fe00",
        is_extended_id=True,
    )
    j1939_tp_cm["protocol"] = "j1939"
    path.write_text(
        "\n".join(json.dumps(item) for item in (uds_request, canopen_nmt, j1939_tp_cm)) + "\n",
        encoding="utf-8",
    )

    report = check_replay(path)

    assert report["protocol_observations"]["uds"]["service_id_counts"] == {"0x10": 1}
    assert report["protocol_observations"]["uds"]["stateful_sequence_count"] == 1
    assert report["protocol_observations"]["cosic"]["nmt_commands"] == {"0x01": 1}
    assert report["protocol_observations"]["cosic"]["stateful_sequence_count"] == 1
    assert report["protocol_observations"]["j1939"]["tp_cm_frames"] == 1
    assert report["state_context"]["stateful_replay_supported"] is False
    assert report["state_context"]["stateful_sequences_detected"] == 2
    assert "responses" in report["state_context"]["reason"]
