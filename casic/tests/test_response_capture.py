import argparse
import json
from collections import deque
from types import SimpleNamespace

import pytest

from casic.cli.config_runner import _build_common, run_from_yaml
from casic.cli.health_report import build_health_report
from casic.cli.main import _add_common_arguments, _config_from_args
from casic.cli.main import main_cansic, main_cosic, main_j1939sic, main_udsic
from casic.core.logging import PacketLogger
from casic.core.models import CANFrame, FuzzConfig
from casic.core.transport import socketcan
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer, UDSFuzzer


def config(**overrides):
    values = dict(interface="unused", rate_mode=1, source_mode="rand",
                  destination="rand", packet_count=1, print_interval=0, seed=7)
    values.update(overrides)
    return FuzzConfig(**values)


@pytest.fixture
def bus(monkeypatch):
    class Bus:
        def __init__(self):
            self.messages = deque()
            self.sent = []
            self.closed = False

        def send(self, message):
            self.sent.append(message)

        def recv(self, timeout=0):
            return self.messages.popleft() if self.messages else None

        def shutdown(self):
            self.closed = True

    instance = Bus()
    monkeypatch.setattr(socketcan, "can", SimpleNamespace(
        interface=SimpleNamespace(Bus=lambda **kwargs: instance),
        Message=lambda **kwargs: SimpleNamespace(**kwargs),
    ))
    return instance


def message(can_id=0x123, data=b"\x03\x7f\x10\x11", extended=False):
    return SimpleNamespace(arbitration_id=can_id, data=data,
                           is_extended_id=extended, is_fd=False, timestamp=123.5)


@pytest.mark.parametrize("fuzzer_class", [RawCANFuzzer, UDSFuzzer, J1939Fuzzer, CANopenFuzzer])
def test_capture_all_observed_frames_including_filtered(tmp_path, bus, fuzzer_class):
    path = tmp_path / "responses.jsonl"
    bus.messages.extend([message(), message(0x456)])
    fuzzer = fuzzer_class(config(save_responses=True, responses_file=path,
                                  response_drain_seconds=0, uds_response_id=0x456))
    result = fuzzer.run()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 2
    assert [row["frame"]["can_id"] for row in rows] == [0x123, 0x456]
    assert rows[0]["frame"]["data"] == "037f1011"
    assert rows[0]["frame"]["timestamp"] > 1000000000
    assert rows[0]["frame"]["meta"]["adapter_timestamp"] == 123.5
    assert rows[0]["frame"]["meta"]["timestamp_source"] == "host_receive"
    assert all(row["event"] == "received" and row["run_id"] == result.run_id for row in rows)
    if fuzzer_class is UDSFuzzer:
        assert [row["accepted"] for row in rows] == [False, True]
        assert result.received == 1
    if fuzzer_class is CANopenFuzzer:
        assert result.received == 0
    assert bus.closed


def test_default_does_not_create_capture_or_poll_raw(tmp_path, bus):
    path = tmp_path / "responses.jsonl"
    bus.messages.append(message())
    fuzzer = RawCANFuzzer(config(responses_file=path))
    fuzzer.run()
    assert not path.exists()
    assert len(bus.messages) == 1


def test_default_path_and_empty_capture(tmp_path, monkeypatch, bus):
    monkeypatch.chdir(tmp_path)
    RawCANFuzzer(config(save_responses=True, response_drain_seconds=0)).run()
    assert (tmp_path / "cansic_responses.jsonl").read_text() == ""


def test_final_drain_collects_delayed_response(tmp_path, bus):
    path = tmp_path / "rx.jsonl"
    bus.messages.extend([None, message()])
    result = RawCANFuzzer(config(save_responses=True, responses_file=path,
                                response_drain_seconds=0.01)).run()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 1 and rows[0]["phase"] == "drain"
    assert result.received == 1


@pytest.mark.parametrize("fuzzer_class", [RawCANFuzzer, UDSFuzzer, J1939Fuzzer, CANopenFuzzer])
def test_error_and_remote_frames_never_reach_feedback_or_correlation(tmp_path, bus, monkeypatch, fuzzer_class):
    output = tmp_path / "rx.jsonl"
    summary = tmp_path / "summary.json"
    error = message(0x58A)
    error.is_error_frame = True
    remote = message(0x58A)
    remote.is_remote_frame = True
    bus.messages.extend([error, remote, message(0x58A), message(0x123)])
    fuzzer = fuzzer_class(config(save_responses=True, responses_file=output,
                                  response_drain_seconds=0, uds_response_id=0x58A,
                                  sdo_tx_cobid=0x58A, summary_enabled=True,
                                  summary_file=summary))
    feedback = []
    monkeypatch.setattr(fuzzer, "on_response", feedback.append)
    result = fuzzer.run()
    assert result.observed_frames == 4
    assert result.can_error_frames == result.remote_frames == 1
    assert result.ordinary_received == 2
    expected = 1 if fuzzer_class in {UDSFuzzer, CANopenFuzzer} else 2
    assert result.received == len(feedback) == len(fuzzer.logger.received) == expected
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["frame_kind"] for row in rows] == ["can_error", "remote", "data", "data"]
    assert [row["accepted"] for row in rows[:2]] == [False, False]
    totals = json.loads(summary.read_text())["totals"]
    assert totals["can_error_frames"] == totals["remote_frames"] == 1
    report = build_health_report([summary], [])["runs"][0]
    assert report["summary"]["ordinary_received"] == 2
    assert any(item["kind"] == "can_error_frames_observed" for item in report["triage_signals"])


@pytest.mark.parametrize("adapter_timestamp", [591250.5, 1793274014.5])
def test_host_timestamp_allows_uds_correlation_across_adapter_clock_domains(bus, monkeypatch, adapter_timestamp):
    monkeypatch.setattr(socketcan.time, "time", lambda: 1793274014.55)
    received = message(0x7E8, bytes.fromhex("0250010000000000"))
    received.timestamp = adapter_timestamp
    bus.messages.append(received)
    fuzzer = UDSFuzzer(config(uds_response_id=0x7E8))
    fuzzer.logger.record_sent(CANFrame(0x7E0, bytes.fromhex("0210010000000000"),
                                     timestamp=1793274014.5))
    fuzzer.monitor_response()
    rows = fuzzer.logger.build_correlation_rows("uds", fuzzer.run_id, 2.0)
    assert rows[0].match_status == "matched"
    assert rows[0].latency_ms == 50.0
    assert fuzzer.logger.received[0].meta["adapter_timestamp"] == adapter_timestamp
    fuzzer.transport.close()


@pytest.mark.parametrize("operation", ["open", "send", "receive", "close"])
def test_transport_errors_saved_and_counted(tmp_path, bus, monkeypatch, operation):
    def fail(*args, **kwargs):
        raise RuntimeError(f"{operation} failed")

    if operation == "open":
        monkeypatch.setattr(socketcan.can.interface, "Bus", fail)
    else:
        monkeypatch.setattr(bus, {"send": "send", "receive": "recv", "close": "shutdown"}[operation], fail)
    path = tmp_path / "rx.jsonl"
    summary = tmp_path / "summary.json"
    result = RawCANFuzzer(config(save_responses=True, responses_file=path,
                                response_drain_seconds=0, summary_enabled=True,
                                summary_file=summary)).run()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    errors = [row for row in rows if row["event"] == "transport_error"]
    assert len(errors) == 1
    assert errors[0]["operation"] == operation
    assert errors[0]["error_type"] == "RuntimeError"
    assert result.transport_errors == 1
    assert json.loads(summary.read_text())["totals"]["transport_errors"] == 1
    report = build_health_report([summary], [])
    assert any(signal["kind"] == "transport_errors_recorded" for signal in report["runs"][0]["triage_signals"])
    if operation == "send":
        assert errors[0]["frame"]["data"]


def test_capture_write_failure_is_explicit_and_closes_bus(tmp_path, bus):
    fuzzer = RawCANFuzzer(config(save_responses=True, responses_file=tmp_path))
    with pytest.raises(OSError):
        fuzzer.run()
    assert bus.closed


def test_capture_configuration_yaml_and_cli():
    parser = argparse.ArgumentParser()
    _add_common_arguments(parser)
    args = parser.parse_args(["-i", "unused", "--save-responses", "--responses-file", "rx.jsonl",
                              "--response-drain-seconds", "0.5", "--raw-feedback-probability", "0.4",
                              "--canopen-feedback-probability", "0.3", "--j1939-feedback-probability", "0.2"])
    cli = _config_from_args(args)
    yaml = _build_common("cansic", {"save_responses": True, "responses_file": "rx.jsonl",
                                   "response_drain_seconds": 0.5, "raw_feedback_probability": 0.4,
                                   "canopen_feedback_probability": 0.3,
                                   "j1939_feedback_probability": 0.2}, {})
    for field in ("save_responses", "responses_file", "response_drain_seconds",
                  "raw_feedback_probability", "canopen_feedback_probability", "j1939_feedback_probability"):
        assert getattr(cli, field) == getattr(yaml, field)
    assert not _build_common("udsic", {"save_responses": True}, {"save_responses": False}).save_responses


@pytest.mark.parametrize("values", [
    {"save_responses": "false"}, {"response_drain_seconds": -1},
    {"response_drain_seconds": float("nan")}, {"response_drain_seconds": 61},
    {"raw_feedback_probability": 1.1}, {"canopen_feedback_probability": -1},
    {"j1939_feedback_probability": float("nan")},
])
def test_invalid_capture_settings(values):
    with pytest.raises(ValueError):
        config(**values)


def test_capture_paths_do_not_change_run_identity():
    assert PacketLogger.deterministic_run_id("uds", config()) == PacketLogger.deterministic_run_id(
        "uds", config(save_responses=True, response_drain_seconds=1))


def test_replay_also_captures_rx(tmp_path, bus):
    replay = tmp_path / "sent.jsonl"
    logger = PacketLogger()
    logger.record_sent(CANFrame(0x123, b"\x01"))
    logger.save_replay("cansic", replay)
    output = tmp_path / "rx.jsonl"
    bus.messages.append(message())
    RawCANFuzzer(config(replay_file=replay, save_responses=True,
                        responses_file=output, response_drain_seconds=0)).run()
    assert json.loads(output.read_text())["phase"] == "replay"


def test_capture_cannot_overwrite_replay_input(tmp_path, bus):
    replay = tmp_path / "input.jsonl"
    replay.write_text("original")
    fuzzer = RawCANFuzzer(config(save_responses=True, responses_file=replay, replay_file=replay))
    with pytest.raises(ValueError, match="must differ"):
        fuzzer.run()
    assert replay.read_text() == "original"
    assert not bus.sent
    assert bus.closed


def test_yaml_rejects_shared_capture_path_before_running(tmp_path, bus):
    yaml = tmp_path / "config.yaml"
    yaml.write_text("global:\n  save_responses: true\n  responses_file: shared.jsonl\n"
                    "protocols:\n  cansic:\n    enabled: true\n  udsic:\n    enabled: true\n")
    with pytest.raises(ValueError, match="distinct"):
        run_from_yaml(yaml)
    assert not bus.sent


def test_capture_failure_mid_run_is_not_silenced(tmp_path, bus, monkeypatch):
    fuzzer = RawCANFuzzer(config(save_responses=True, responses_file=tmp_path / "rx.jsonl",
                                response_drain_seconds=0))
    bus.messages.append(message())

    def fail(event):
        raise OSError("disk full")

    monkeypatch.setattr(fuzzer, "_write_capture", fail)
    with pytest.raises(OSError, match="disk full"):
        fuzzer.run()
    assert bus.closed


def test_raw_feedback_polls_without_saving(tmp_path, bus):
    path = tmp_path / "disabled.jsonl"
    bus.messages.append(message())
    fuzzer = RawCANFuzzer(config(raw_feedback_probability=1, responses_file=path))
    fuzzer.run()
    assert fuzzer._observed_templates
    assert not path.exists()


@pytest.mark.parametrize("main", [main_cansic, main_cosic, main_j1939sic, main_udsic])
def test_cli_creates_capture_when_explicitly_enabled(tmp_path, bus, main):
    output = tmp_path / "rx.jsonl"
    bus.messages.append(message())
    main(["-i", "unused", "-p", "1", "-m", "0", "--save-responses",
          "--responses-file", str(output), "--response-drain-seconds", "0"])
    assert json.loads(output.read_text())["event"] == "received"


def test_yaml_creates_distinct_default_captures_for_all_protocols(tmp_path, bus, monkeypatch):
    monkeypatch.chdir(tmp_path)
    yaml = tmp_path / "config.yaml"
    yaml.write_text("global:\n  interface: unused\n  packet_count: 1\n  print_interval: 0\n"
                    "  save_responses: true\n  response_drain_seconds: 0\n"
                    "protocols:\n  cansic:\n    enabled: true\n  udsic:\n    enabled: true\n"
                    "  j1939sic:\n    enabled: true\n  cosic:\n    enabled: true\n")
    run_from_yaml(yaml)
    for protocol in ("cansic", "uds", "j1939", "cosic"):
        assert (tmp_path / f"{protocol}_responses.jsonl").exists()
