from __future__ import annotations

import argparse
import json
import math
import time
from collections import Counter
from pathlib import Path
from typing import Any

from casic.cli.yaml_config import load_yaml, parse_int


def _parse_duration(value: str) -> float:
    try:
        duration = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("duration must be a number") from exc
    if not math.isfinite(duration) or not 1.0 <= duration <= 60.0:
        raise argparse.ArgumentTypeError("duration must be between 1 and 60 seconds")
    return duration


def _pcan_channel(interface: str) -> str:
    value = interface.strip()
    if ":" in value:
        prefix, channel = value.split(":", 1)
        if prefix.strip().lower() != "pcan":
            raise ValueError(f"receive-only check requires a PCAN interface, got {interface!r}")
        value = channel.strip()
    elif not (value.upper().startswith("PCAN_") or "USBBUS" in value.upper()):
        raise ValueError(f"receive-only check requires a PCAN channel, got {interface!r}")
    if not value:
        raise ValueError("PCAN channel must not be empty")
    return value


def _expected_response_ids(config: dict[str, Any]) -> dict[str, int]:
    protocols = config.get("protocols", {})
    if not isinstance(protocols, dict):
        return {}
    expected: dict[str, int] = {}

    uds = protocols.get("udsic")
    if isinstance(uds, dict) and uds.get("enabled", False):
        response_id = parse_int(uds.get("uds_response_id"))
        if response_id is not None:
            expected["uds_response_id"] = response_id

    canopen = protocols.get("cosic")
    if isinstance(canopen, dict) and canopen.get("enabled", False):
        sdo_tx = parse_int(canopen.get("sdo_tx_cobid"))
        node_id = parse_int(canopen.get("node_id"))
        if sdo_tx is None and node_id is not None:
            sdo_tx = 0x580 + node_id
        if sdo_tx is not None:
            expected["canopen_sdo_response_id"] = sdo_tx

    return expected


def _read_only_capture(interface: str, bitrate: int, duration_seconds: float) -> dict[str, Any]:
    try:
        import can
    except ImportError as exc:
        raise RuntimeError("python-can is required; install the optional CAN dependency with `pip install .[can]`") from exc

    channel = _pcan_channel(interface)
    bus = None
    try:
        bus = can.Bus(
            interface="pcan",
            channel=channel,
            bitrate=bitrate,
            state=can.BusState.PASSIVE,
            receive_own_messages=False,
        )
        bus.state = can.BusState.PASSIVE
        if bus.state != can.BusState.PASSIVE:
            raise RuntimeError("PCAN adapter did not confirm passive/listen-only state; refusing to continue")

        counts: Counter[str] = Counter()
        extended_count = 0
        fd_count = 0
        payload_sizes: Counter[str] = Counter()
        started = time.time()
        deadline = time.monotonic() + duration_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            message = bus.recv(timeout=remaining)
            if message is None:
                continue
            can_id = int(message.arbitration_id)
            counts[f"0x{can_id:X}"] += 1
            extended_count += bool(message.is_extended_id)
            fd_count += bool(message.is_fd)
            payload_sizes[str(len(message.data))] += 1

        return {
            "schema_version": 1,
            "interface": interface,
            "channel": channel,
            "bitrate": bitrate,
            "mode": "passive_listen_only",
            "transmitted_frames": 0,
            "duration_seconds": duration_seconds,
            "started_at": started,
            "ended_at": time.time(),
            "frames_observed": sum(counts.values()),
            "extended_frames_observed": extended_count,
            "can_fd_frames_observed": fd_count,
            "payload_length_counts": dict(sorted(payload_sizes.items(), key=lambda item: int(item[0]))),
            "observed_ids": dict(counts.most_common(100)),
            "status": "frames_observed" if counts else "no_frames_observed",
            "interpretation": [
                "The PCAN adapter was opened in passive/listen-only mode and no frames were transmitted by this command.",
                "An observed identifier only confirms bus traffic during this observation window; it does not prove which device sent it.",
                "No observed frames does not prove that the adapter or target is faulty; the bus may be idle or bitrate/channel settings may differ.",
                "This check does not run fuzzers, validate device health, or verify protocol responses.",
            ],
        }
    finally:
        if bus is not None:
            bus.shutdown()


def check_pcan(config_path: Path, duration_seconds: float, interface_override: str | None = None) -> dict[str, Any]:
    config = load_yaml(config_path)
    global_config = config.get("global", {})
    if not isinstance(global_config, dict):
        raise ValueError("YAML 'global' section must be a mapping")
    interface = interface_override or str(global_config.get("interface", ""))
    bitrate = parse_int(global_config.get("bitrate")) or 500000
    if not 10000 <= bitrate <= 1000000:
        raise ValueError(f"bitrate must be in range 10000..1000000, got {bitrate}")

    report = _read_only_capture(interface, bitrate, duration_seconds)
    report["config_file"] = str(config_path)
    expected = _expected_response_ids(config)
    report["configured_response_id_checks"] = {
        name: {
            "can_id": f"0x{can_id:X}",
            "observed": report["observed_ids"].get(f"0x{can_id:X}", 0) > 0,
        }
        for name, can_id in expected.items()
    }
    if expected:
        report["interpretation"].append(
            "Configured response-ID presence is checked only against this short passive sample; absence is inconclusive."
        )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casic-pcan-check",
        description="Passively observe a PCAN channel; this command never sends CAN frames.",
    )
    parser.add_argument("--config", type=Path, required=True, help="CASIC YAML config whose PCAN channel to inspect")
    parser.add_argument("--interface", help="Optional PCAN channel override")
    parser.add_argument("--duration", type=_parse_duration, default=5.0, help="Observation time in seconds (1..60)")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args(argv)

    try:
        report = check_pcan(args.config, args.duration, args.interface)
        output = json.dumps(report, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output + "\n", encoding="utf-8")
            print(f"Passive PCAN report written to {args.output}")
        else:
            print(output)
    except (OSError, RuntimeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
