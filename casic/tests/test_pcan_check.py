from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import can
import pytest

from casic.cli.pcan_check import _expected_response_ids, _pcan_channel, _read_only_capture, check_pcan


def test_pcan_channel_requires_pcan_backend():
    assert _pcan_channel("pcan:PCAN_USBBUS1") == "PCAN_USBBUS1"
    assert _pcan_channel("PCAN_USBBUS1") == "PCAN_USBBUS1"
    with pytest.raises(ValueError, match="requires a PCAN"):
        _pcan_channel("can0")


def test_expected_response_ids_derive_configured_uds_and_canopen_ids():
    config = {
        "protocols": {
            "udsic": {"enabled": True, "uds_response_id": "0x7E8"},
            "cosic": {"enabled": True, "node_id": 10},
        }
    }

    assert _expected_response_ids(config) == {
        "uds_response_id": 0x7E8,
        "canopen_sdo_response_id": 0x58A,
    }


def test_read_only_capture_uses_passive_state_and_never_sends(monkeypatch):
    received = SimpleNamespace(
        arbitration_id=0x7E8,
        is_extended_id=False,
        is_fd=False,
        data=b"\x03\x7F\x10\x78",
    )

    class FakeBus:
        def __init__(self):
            self._state = None
            self.shutdown_called = False
            self.recv_calls = 0

        @property
        def state(self):
            return self._state

        @state.setter
        def state(self, value):
            self._state = value

        def recv(self, timeout):
            self.recv_calls += 1
            return received if self.recv_calls == 1 else None

        def send(self, message):
            raise AssertionError("passive validation must never send")

        def shutdown(self):
            self.shutdown_called = True

    fake_bus = FakeBus()
    monkeypatch.setattr(can, "Bus", lambda **kwargs: fake_bus)
    monotonic_values = iter([10.0, 10.1, 11.0])
    monkeypatch.setattr("casic.cli.pcan_check.time.monotonic", lambda: next(monotonic_values))

    report = _read_only_capture("pcan:PCAN_USBBUS1", 500000, 1.0)

    assert report["mode"] == "passive_listen_only"
    assert report["transmitted_frames"] == 0
    assert report["frames_observed"] == 1
    assert report["observed_ids"] == {"0x7E8": 1}
    assert fake_bus.state == can.BusState.PASSIVE
    assert fake_bus.shutdown_called is True


def test_check_pcan_rejects_non_pcan_interface_without_opening_bus(tmp_path: Path):
    config = tmp_path / "casic.yaml"
    config.write_text(
        """
global:
  interface: can0
protocols: {}
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="requires a PCAN"):
        check_pcan(config, 1.0)
