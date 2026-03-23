from __future__ import annotations

import csv
import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from casic.core.models import CANFrame, CorrelationRow, ProtocolRunSummary, ReplayRecord


class PacketLogger:
    def __init__(self):
        self.sent: list[CANFrame] = []
        self.received: list[CANFrame] = []

    def record_sent(self, frame: CANFrame):
        frame.timestamp = frame.timestamp or time.time()
        self.sent.append(frame)

    def record_received(self, frame: CANFrame):
        frame.timestamp = frame.timestamp or time.time()
        self.received.append(frame)

    def correlate(self, window_seconds: float = 0.5) -> list[tuple[CANFrame, CANFrame]]:
        pairs: list[tuple[CANFrame, CANFrame]] = []
        for request in self.sent:
            for response in self.received:
                if response.timestamp is None or request.timestamp is None:
                    continue
                delta = response.timestamp - request.timestamp
                if 0 <= delta <= window_seconds:
                    pairs.append((request, response))
                    break
        return pairs

    @staticmethod
    def _frame_to_json(frame: CANFrame) -> dict[str, Any]:
        frame_dict = asdict(frame)
        frame_dict["data"] = frame.data.hex()
        burst_frames = frame.meta.get("burst", [])
        if burst_frames:
            frame_dict["meta"] = dict(frame_dict.get("meta", {}))
            frame_dict["meta"]["burst"] = [PacketLogger._frame_to_json(item) for item in burst_frames]
        return frame_dict

    @staticmethod
    def _frame_from_json(frame_data: dict[str, Any]) -> CANFrame:
        meta = dict(frame_data.get("meta", {}))
        burst_items = meta.get("burst", [])
        burst_frames: list[CANFrame] = []
        for item in burst_items:
            if isinstance(item, dict):
                burst_frames.append(PacketLogger._frame_from_json(item))
        if burst_frames:
            meta["burst"] = burst_frames

        return CANFrame(
            can_id=int(frame_data["can_id"]),
            data=bytes.fromhex(frame_data["data"]),
            is_extended_id=bool(frame_data.get("is_extended_id", False)),
            is_fd=bool(frame_data.get("is_fd", False)),
            timestamp=frame_data.get("timestamp"),
            meta=meta,
        )

    def save_replay(
        self,
        protocol: str,
        path: Path,
        note: str = "",
        run_id: str | None = None,
        seed: int | None = None,
        profile_name: str | None = None,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for frame in self.sent:
                record = ReplayRecord(
                    protocol=protocol,
                    frame=frame,
                    note=note,
                    run_id=run_id,
                    seed=seed,
                    profile_name=profile_name,
                )
                data = asdict(record)
                data["frame"] = self._frame_to_json(frame)
                handle.write(json.dumps(data) + "\n")

    def load_replay(self, path: Path) -> list[ReplayRecord]:
        entries: list[ReplayRecord] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = json.loads(line)
                frame = self._frame_from_json(raw["frame"])
                entries.append(
                    ReplayRecord(
                        protocol=raw["protocol"],
                        frame=frame,
                        note=raw.get("note", ""),
                        run_id=raw.get("run_id"),
                        seed=raw.get("seed"),
                        profile_name=raw.get("profile_name"),
                    )
                )
        return entries

    @staticmethod
    def deterministic_run_id(protocol: str, config: Any) -> str:
        payload = asdict(config)
        for ephemeral_key in (
            "summary_enabled",
            "summary_file",
            "correlation_enabled",
            "correlation_report_file",
            "correlation_window_seconds",
            "save_replay_file",
            "profile_name",
            "print_interval",
        ):
            payload.pop(ephemeral_key, None)
        for key, value in list(payload.items()):
            if isinstance(value, Path):
                payload[key] = str(value)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(f"{protocol}:{canonical}".encode("utf-8")).hexdigest()
        return digest[:16]

    @staticmethod
    def write_run_summary(path: Path, runs: list[ProtocolRunSummary]):
        path.parent.mkdir(parents=True, exist_ok=True)
        totals = {
            "sent": sum(item.sent for item in runs),
            "received": sum(item.received for item in runs),
            "errors": sum(item.errors for item in runs),
            "burst_frames": sum(item.burst_frames for item in runs),
            "duration_ms": round(sum(item.duration_ms for item in runs), 3),
        }
        payload = {
            "schema_version": 1,
            "generated_at": time.time(),
            "run_count": len(runs),
            "totals": totals,
            "runs": [asdict(item) for item in runs],
        }
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    @staticmethod
    def _uds_request_context(frame: CANFrame) -> dict[str, Any]:
        if not frame.data:
            return {"service": None, "subfunction": None, "can_id": frame.can_id}
        pci_type = (frame.data[0] >> 4) & 0x0F
        if pci_type == 0:
            length = frame.data[0] & 0x0F
            payload = bytes(frame.data[1 : 1 + length])
        else:
            payload = bytes(frame.data[1:])
        sid = payload[0] if payload else None
        subfunction = payload[1] if len(payload) > 1 else None
        return {"service": sid, "subfunction": subfunction, "can_id": frame.can_id}

    @staticmethod
    def _uds_response_context(frame: CANFrame) -> dict[str, Any]:
        context = PacketLogger._uds_request_context(frame)
        service = context.get("service")
        if service is None:
            context["request_service"] = None
            return context
        if service == 0x7F and len(frame.data) >= 4:
            context["request_service"] = frame.data[2]
            context["nrc"] = frame.data[3]
            return context
        if service >= 0x40:
            context["request_service"] = service - 0x40
            return context
        context["request_service"] = service
        return context

    @staticmethod
    def _j1939_context(frame: CANFrame) -> dict[str, Any]:
        can_id = frame.can_id
        pf = (can_id >> 16) & 0xFF
        ps = (can_id >> 8) & 0xFF
        sa = can_id & 0xFF
        if pf < 240:
            pgn = pf << 8
            da = ps
        else:
            pgn = (pf << 8) | ps
            da = 0xFF
        return {"pgn": pgn, "sa": sa, "da": da}

    def build_correlation_rows(
        self,
        protocol: str,
        run_id: str,
        window_seconds: float,
    ) -> list[CorrelationRow]:
        if protocol not in {"uds", "j1939"}:
            return []

        def key_and_context(frame: CANFrame, is_response: bool) -> tuple[str, dict[str, Any]]:
            if protocol == "uds":
                if is_response:
                    ctx = self._uds_response_context(frame)
                    key = f"service:{ctx.get('request_service')}"
                else:
                    ctx = self._uds_request_context(frame)
                    key = f"service:{ctx.get('service')}"
                return key, ctx

            ctx = self._j1939_context(frame)
            key = f"pgn:{ctx['pgn']}|sa:{ctx['sa']}|da:{ctx['da']}"
            return key, ctx

        rows: list[CorrelationRow] = []
        consumed_responses: set[int] = set()
        for request in self.sent:
            request_key, request_ctx = key_and_context(request, is_response=False)
            match_index: int | None = None
            latency_ms: float | None = None

            for idx, response in enumerate(self.received):
                if idx in consumed_responses:
                    continue
                if request.timestamp is None or response.timestamp is None:
                    continue
                if response.timestamp < request.timestamp:
                    continue

                response_key, response_ctx = key_and_context(response, is_response=True)
                delta = response.timestamp - request.timestamp
                if response_key == request_key and delta <= window_seconds:
                    match_index = idx
                    latency_ms = round(delta * 1000.0, 3)
                    consumed_responses.add(idx)
                    rows.append(
                        CorrelationRow(
                            protocol=protocol,
                            run_id=run_id,
                            request_timestamp=request.timestamp,
                            response_timestamp=response.timestamp,
                            match_status="matched",
                            latency_ms=latency_ms,
                            correlation_key=request_key,
                            request_context=request_ctx,
                            response_context=response_ctx,
                        )
                    )
                    break

            if match_index is None:
                rows.append(
                    CorrelationRow(
                        protocol=protocol,
                        run_id=run_id,
                        request_timestamp=request.timestamp,
                        response_timestamp=None,
                        match_status="unmatched",
                        latency_ms=None,
                        correlation_key=request_key,
                        request_context=request_ctx,
                        response_context={},
                    )
                )
        return rows

    @staticmethod
    def _percentile(sorted_values: list[float], percentile: int) -> float | None:
        if not sorted_values:
            return None
        if len(sorted_values) == 1:
            return sorted_values[0]
        rank = max(0, min(len(sorted_values) - 1, round((percentile / 100) * (len(sorted_values) - 1))))
        return sorted_values[rank]

    @staticmethod
    def write_correlation_csv(
        path: Path,
        protocol: str,
        run_id: str,
        rows: list[CorrelationRow],
        unsupported_reason: str | None = None,
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        latencies = sorted([row.latency_ms for row in rows if row.latency_ms is not None])
        matched = sum(1 for row in rows if row.match_status == "matched")
        unmatched = sum(1 for row in rows if row.match_status == "unmatched")
        total = len(rows)
        match_rate = 0.0 if total == 0 else round((matched / total) * 100.0, 3)

        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(
                [
                    "protocol",
                    "run_id",
                    "request_timestamp",
                    "response_timestamp",
                    "match_status",
                    "latency_ms",
                    "correlation_key",
                    "request_context",
                    "response_context",
                    "summary_metric",
                    "summary_value",
                ]
            )

            if unsupported_reason is not None:
                writer.writerow(
                    [protocol, run_id, "", "", "unsupported", "", "", "", "", "unsupported_reason", unsupported_reason]
                )

            for row in rows:
                writer.writerow(
                    [
                        row.protocol,
                        row.run_id,
                        row.request_timestamp,
                        row.response_timestamp,
                        row.match_status,
                        row.latency_ms,
                        row.correlation_key,
                        json.dumps(row.request_context, sort_keys=True),
                        json.dumps(row.response_context, sort_keys=True),
                        "",
                        "",
                    ]
                )

            metrics = {
                "match_rate_percent": match_rate,
                "unmatched_requests": unmatched,
                "latency_p50_ms": PacketLogger._percentile(latencies, 50),
                "latency_p90_ms": PacketLogger._percentile(latencies, 90),
                "latency_p95_ms": PacketLogger._percentile(latencies, 95),
                "latency_p99_ms": PacketLogger._percentile(latencies, 99),
            }
            for key, value in metrics.items():
                writer.writerow([protocol, run_id, "", "", "", "", "", "", "", key, value])
