from __future__ import annotations

import argparse
import json
import math
import time
from collections import Counter
from pathlib import Path
from typing import Any


_KNOWN_PROTOCOLS = {"cansic", "uds", "j1939", "cosic"}
_CLASSIC_LENGTHS = set(range(9))
_FD_LENGTHS = {0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64}
_STATEFUL_UDS_SERVICES = {
    0x10: "diagnostic session control",
    0x11: "ECU reset",
    0x27: "security access",
    0x28: "communication control",
    0x2E: "write data by identifier",
    0x31: "routine control",
    0x34: "request download",
    0x36: "transfer data",
    0x37: "request transfer exit",
    0x85: "control DTC setting",
}
_CANOPEN_NMT_COMMANDS = {
    0x01: "start remote node",
    0x02: "stop remote node",
    0x80: "enter pre-operational",
    0x81: "reset node",
    0x82: "reset communication",
}


def _observe_protocol_frame(protocol: str, frame: dict[str, Any], observations: dict[str, Any]):
    try:
        payload = bytes.fromhex(frame["data"])
    except (KeyError, TypeError, ValueError):
        return
    can_id = frame.get("can_id")
    if isinstance(can_id, bool) or not isinstance(can_id, int):
        return

    if protocol == "uds":
        details = observations.setdefault(
            protocol,
            {
                "frame_count": 0,
                "isotp_pci_type_counts": Counter(),
                "service_id_counts": Counter(),
                "stateful_sequence_count": 0,
                "stateful_sequence_examples": [],
            },
        )
        details["frame_count"] += 1
        if not payload:
            return
        pci_type = payload[0] >> 4
        details["isotp_pci_type_counts"][str(pci_type)] += 1
        if pci_type == 0:
            application = payload[1 : 1 + (payload[0] & 0x0F)]
        elif pci_type == 1:
            application = payload[2:]
        else:
            return
        if application:
            service = application[0]
            details["service_id_counts"][f"0x{service:02X}"] += 1
            if service in _STATEFUL_UDS_SERVICES:
                details["stateful_sequence_count"] += 1
                if len(details["stateful_sequence_examples"]) < 50:
                    details["stateful_sequence_examples"].append(
                        {
                            "can_id": f"0x{can_id:X}",
                            "service_id": f"0x{service:02X}",
                            "service": _STATEFUL_UDS_SERVICES[service],
                        }
                    )
        return

    if protocol == "j1939" and frame.get("is_extended_id") is True:
        details = observations.setdefault(
            protocol,
            {"frame_count": 0, "pgn_counts": Counter(), "tp_cm_frames": 0, "tp_dt_frames": 0},
        )
        details["frame_count"] += 1
        pf = (can_id >> 16) & 0xFF
        ps = (can_id >> 8) & 0xFF
        pgn = (pf << 8) if pf < 240 else (pf << 8) | ps
        details["pgn_counts"][f"0x{pgn:05X}"] += 1
        if pgn == 0xEC00:
            details["tp_cm_frames"] += 1
        elif pgn == 0xEB00:
            details["tp_dt_frames"] += 1
        return

    if protocol == "cosic":
        details = observations.setdefault(
            protocol,
            {
                "frame_count": 0,
                "nmt_commands": Counter(),
                "sdo_client_commands": Counter(),
                "sdo_server_responses": 0,
                "stateful_sequence_count": 0,
                "stateful_sequence_examples": [],
            },
        )
        details["frame_count"] += 1
        if can_id == 0 and payload:
            command = payload[0]
            details["nmt_commands"][f"0x{command:02X}"] += 1
            if command in _CANOPEN_NMT_COMMANDS:
                details["stateful_sequence_count"] += 1
                if len(details["stateful_sequence_examples"]) < 50:
                    details["stateful_sequence_examples"].append(
                        {
                            "can_id": f"0x{can_id:X}",
                            "command": f"0x{command:02X}",
                            "action": _CANOPEN_NMT_COMMANDS[command],
                        }
                    )
        elif 0x600 <= can_id <= 0x67F and payload:
            command = payload[0]
            details["sdo_client_commands"][f"0x{command:02X}"] += 1
            if command & 0xE0 == 0x20:
                details["stateful_sequence_count"] += 1
                if len(details["stateful_sequence_examples"]) < 50:
                    details["stateful_sequence_examples"].append(
                        {
                            "can_id": f"0x{can_id:X}",
                            "command": f"0x{command:02X}",
                            "action": "CANopen SDO initiate download",
                        }
                    )
        elif 0x580 <= can_id <= 0x5FF:
            details["sdo_server_responses"] += 1


def _json_safe_observations(observations: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for protocol, details in observations.items():
        result[protocol] = {
            key: dict(value) if isinstance(value, Counter) else value
            for key, value in details.items()
        }
    return result


def _validate_frame(frame: Any, label: str, issues: list[dict[str, Any]], depth: int = 0):
    if depth > 16:
        issues.append({"line": label, "severity": "error", "message": "burst nesting exceeds maximum depth 16"})
        return
    if not isinstance(frame, dict):
        issues.append({"line": label, "severity": "error", "message": "frame must be a JSON object"})
        return
    for field in ("can_id", "data"):
        if field not in frame:
            issues.append({"line": label, "severity": "error", "message": f"frame is missing {field!r}"})
    if "can_id" not in frame or "data" not in frame:
        return

    can_id = frame["can_id"]
    if isinstance(can_id, bool) or not isinstance(can_id, int):
        issues.append({"line": label, "severity": "error", "message": "can_id must be an integer"})
        return
    is_extended = frame.get("is_extended_id", False)
    if not isinstance(is_extended, bool):
        issues.append({"line": label, "severity": "error", "message": "is_extended_id must be a boolean"})
    elif not 0 <= can_id <= (0x1FFFFFFF if is_extended else 0x7FF):
        issues.append(
            {
                "line": label,
                "severity": "error",
                "message": f"can_id is outside the {'29-bit' if is_extended else '11-bit'} identifier range",
            }
        )

    is_fd = frame.get("is_fd", False)
    if not isinstance(is_fd, bool):
        issues.append({"line": label, "severity": "error", "message": "is_fd must be a boolean"})
        is_fd = False
    data = frame["data"]
    if not isinstance(data, str):
        issues.append({"line": label, "severity": "error", "message": "frame data must be a hexadecimal string"})
        data_bytes = None
    else:
        try:
            data_bytes = bytes.fromhex(data)
        except ValueError:
            issues.append({"line": label, "severity": "error", "message": "frame data is not valid hexadecimal"})
            data_bytes = None

    if data_bytes is not None:
        if len(data_bytes) > (64 if is_fd else 8):
            issues.append(
                {
                    "line": label,
                    "severity": "error",
                    "message": f"payload length {len(data_bytes)} exceeds the {'CAN-FD' if is_fd else 'classic CAN'} maximum",
                }
            )
        elif is_fd and len(data_bytes) not in _FD_LENGTHS:
            issues.append(
                {
                    "line": label,
                    "severity": "warning",
                    "message": f"CAN-FD payload length {len(data_bytes)} is not a standard on-wire DLC length",
                }
            )

    timestamp = frame.get("timestamp")
    if timestamp is not None and (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
    ):
        issues.append({"line": label, "severity": "error", "message": "timestamp must be a finite number or null"})

    meta = frame.get("meta", {})
    if not isinstance(meta, dict):
        issues.append({"line": label, "severity": "error", "message": "frame meta must be a JSON object"})
        return
    burst = meta.get("burst", [])
    if not isinstance(burst, list):
        issues.append({"line": label, "severity": "error", "message": "meta.burst must be a JSON list"})
        return
    for index, item in enumerate(burst):
        _validate_frame(item, f"{label}.burst[{index}]", issues, depth + 1)


def check_replay(path: Path) -> dict[str, Any]:
    records = 0
    protocols: set[str] = set()
    run_ids: set[str] = set()
    issues: list[dict[str, Any]] = []
    protocol_observations: dict[str, Any] = {}
    previous_timestamp: float | None = None

    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    issues.append(
                        {"line": line_number, "severity": "warning", "message": "blank JSONL line ignored"}
                    )
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    issues.append(
                        {
                            "line": line_number,
                            "severity": "error",
                            "message": f"invalid JSON: {exc.msg}",
                        }
                    )
                    continue

                if not isinstance(record, dict):
                    issues.append(
                        {"line": line_number, "severity": "error", "message": "record must be a JSON object"}
                    )
                    continue
                protocol = record.get("protocol")
                if not isinstance(protocol, str) or not protocol.strip():
                    issues.append(
                        {"line": line_number, "severity": "error", "message": "protocol must be a non-empty string"}
                    )
                else:
                    protocols.add(protocol)
                    if protocol not in _KNOWN_PROTOCOLS:
                        issues.append(
                            {
                                "line": line_number,
                                "severity": "warning",
                                "message": f"unknown protocol label {protocol!r}",
                            }
                        )

                run_id = record.get("run_id")
                if run_id is not None:
                    if not isinstance(run_id, str) or not run_id:
                        issues.append(
                            {"line": line_number, "severity": "error", "message": "run_id must be a non-empty string or null"}
                        )
                    else:
                        run_ids.add(run_id)

                seed = record.get("seed")
                if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
                    issues.append({"line": line_number, "severity": "error", "message": "seed must be an integer or null"})

                if "frame" not in record:
                    issues.append({"line": line_number, "severity": "error", "message": "record is missing 'frame'"})
                    continue
                _validate_frame(record["frame"], line_number, issues)
                frame = record["frame"]
                if isinstance(frame, dict):
                    if isinstance(protocol, str) and protocol in _KNOWN_PROTOCOLS:
                        _observe_protocol_frame(protocol, frame, protocol_observations)
                    timestamp = frame.get("timestamp")
                    if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool) and math.isfinite(timestamp):
                        if previous_timestamp is not None and timestamp < previous_timestamp:
                            issues.append(
                                {
                                    "line": line_number,
                                    "severity": "warning",
                                    "message": "top-level frame timestamp is earlier than the previous record",
                                }
                            )
                        previous_timestamp = float(timestamp)
                records += 1
    except OSError as exc:
        raise ValueError(f"{path}: could not read file: {exc}") from exc

    errors = sum(issue["severity"] == "error" for issue in issues)
    warnings = sum(issue["severity"] == "warning" for issue in issues)
    if records == 0:
        issues.append({"line": None, "severity": "warning", "message": "no replay records found"})
        warnings += 1
    if len(protocols) > 1:
        issues.append(
            {
                "line": None,
                "severity": "warning",
                "message": "file contains multiple protocol labels",
            }
        )
        warnings += 1
    if len(run_ids) > 1:
        issues.append(
            {
                "line": None,
                "severity": "warning",
                "message": "file contains multiple run IDs",
            }
        )
        warnings += 1

    return {
        "schema_version": 1,
        "generated_at": time.time(),
        "source": str(path),
        "valid": errors == 0 and records > 0,
        "record_count": records,
        "protocols": sorted(protocols),
        "run_ids": sorted(run_ids),
        "errors": errors,
        "warnings": warnings,
        "issues": issues,
        "protocol_observations": _json_safe_observations(protocol_observations),
        "state_context": {
            "status": "incomplete",
            "reason": "Replay records contain sent frames only; device responses and accepted state transitions are absent.",
            "stateful_replay_supported": False,
            "stateful_sequences_detected": sum(
                details.get("stateful_sequence_count", 0) for details in protocol_observations.values()
            ),
            "warning": "Detected sequences may change target state if replayed; this checker only reports them and never transmits.",
        },
        "interpretation": [
            "Validation is offline and does not transmit replay frames.",
            "A structurally valid capture does not guarantee equivalent target responses when replayed.",
            "Replay files contain sent frames, not a complete request/response or device-state history.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casic-replay-check",
        description="Validate an existing CASIC JSONL replay file without transmitting frames.",
    )
    parser.add_argument("replay_file", type=Path, help="Replay JSONL file to inspect")
    parser.add_argument("--output", type=Path, help="Optional JSON report path")
    args = parser.parse_args(argv)

    try:
        report = check_replay(args.replay_file)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        else:
            print(json.dumps(report, indent=2))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
