import argparse
from types import SimpleNamespace

import pytest

from casic.cli.config_runner import _build_common
from casic.cli.main import _add_common_arguments, _config_from_args
from casic.core.models import CANFrame, FuzzConfig
from casic.core.transport import socketcan
from casic.protocols.uds import UDSFuzzer


def config(**overrides):
    values = dict(interface="pcan:PCAN_USBBUS1", rate_mode=0, source_mode="rand",
                  destination="rand", packet_count=1, print_interval=0, seed=7)
    values.update(overrides)
    return FuzzConfig(**values)


@pytest.mark.parametrize("bitrate", [0, -1, 1000001, True, 250000.0, "250000"])
def test_invalid_bitrate_rejected(bitrate):
    with pytest.raises(ValueError, match="bitrate"):
        config(bitrate=bitrate)


def test_yaml_and_cli_propagate_bitrate():
    assert _build_common("udsic", {"bitrate": 250000}, {}).bitrate == 250000
    assert _build_common("udsic", {"bitrate": 250000}, {"bitrate": 125000}).bitrate == 125000
    parser = argparse.ArgumentParser()
    _add_common_arguments(parser)
    args = parser.parse_args(["-i", "unused", "--bitrate", "250000"])
    assert _config_from_args(args).bitrate == 250000
    assert config().bitrate == 500000
    with pytest.raises(ValueError, match="boolean"):
        _build_common("udsic", {}, {"uds_extended_id": "false"})


def test_engine_propagates_bitrate_to_pcan(monkeypatch):
    calls = []
    fake_bus = SimpleNamespace(shutdown=lambda: None)
    def open_bus(**kwargs):
        calls.append(kwargs)
        return fake_bus
    monkeypatch.setattr(socketcan, "can", SimpleNamespace(interface=SimpleNamespace(Bus=open_bus)))
    fuzzer = UDSFuzzer(config(bitrate=250000))
    try:
        assert calls == [{"interface": "pcan", "channel": "PCAN_USBBUS1", "bitrate": 250000}]
    finally:
        fuzzer.transport.close()


@pytest.mark.parametrize("extended,request_id", [(False, 0x18DA00F1), (True, 0x321), (False, 0x321)])
@pytest.mark.parametrize("payload_size", [0, 40])
def test_uds_frame_and_burst_identifier_format(monkeypatch, extended, request_id, payload_size):
    monkeypatch.setattr(socketcan, "can", None)
    fuzzer = UDSFuzzer(config(uds_request_id=request_id, uds_extended_id=extended))
    monkeypatch.setattr(fuzzer.rng, "randint", lambda low, high: payload_size if high == 50 else low)
    frame = fuzzer.generate_frame(1)
    expected = extended or request_id > 0x7FF
    assert frame.is_extended_id is expected
    burst = frame.meta.get("burst", [])
    assert bool(burst) == (payload_size == 40)
    assert all(item.is_extended_id is expected and item.can_id == request_id for item in burst)


def test_uds_response_filter_checks_identifier_format(monkeypatch):
    monkeypatch.setattr(socketcan, "can", None)
    fuzzer = UDSFuzzer(config(uds_response_id=0x18DAF100))
    assert fuzzer.should_accept_response(CANFrame(0x18DAF100, b"", is_extended_id=True))
    assert not fuzzer.should_accept_response(CANFrame(0x18DAF100, b"", is_extended_id=False))
    assert not fuzzer.should_accept_response(CANFrame(0x18DAF101, b"", is_extended_id=True))
