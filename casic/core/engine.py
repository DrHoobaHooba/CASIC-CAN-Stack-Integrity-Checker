from __future__ import annotations

import time
import json
import logging
from abc import ABC, abstractmethod
from contextlib import nullcontext
from pathlib import Path
from typing import Any, TextIO

from casic.core.generator import RandomGenerator
from casic.core.logging import PacketLogger
from casic.core.models import CANFrame, FuzzConfig, FuzzStats, ProtocolRunSummary
from casic.core.transport import CanTransport


class BaseFuzzer(ABC):
    protocol_name = "base"
    RATE_MODE0_INTERVAL_SECONDS = 0.001

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.rng = RandomGenerator(seed=config.seed)
        self.logger = PacketLogger()
        self.stats = FuzzStats()
        self._capture_handle: TextIO | None = None
        self._pending_transport_errors: list[dict[str, Any]] = []
        self._capture_phase = "run"
        self.run_id = PacketLogger.deterministic_run_id(self.protocol_name, self.config)
        self.transport = CanTransport(
            interface=config.interface, bitrate=config.bitrate, on_error=self._on_transport_error,
        )
        self._next_send_ts: float | None = None
        self._run_started_at: float | None = None
        self._run_ended_at: float | None = None
        self._burst_frames_sent: int = 0

    def _write_capture(self, event: dict[str, Any]):
        if self._capture_handle is not None:
            record = {
                "schema_version": 1, "protocol": self.protocol_name, "run_id": self.run_id,
                "seed": self.config.seed, "profile_name": self.config.profile_name,
                "interface": self.config.interface, "bitrate": self.config.bitrate,
                "observed_at": time.time(), "phase": self._capture_phase, **event,
            }
            self._capture_handle.write(json.dumps(record) + "\n")
            self._capture_handle.flush()

    def _on_transport_error(self, error: dict[str, Any]):
        self.stats.transport_errors += 1
        event = {"event": "transport_error", **error}
        frame = event.get("frame")
        if isinstance(frame, CANFrame):
            event["frame"] = PacketLogger._frame_to_json(frame)
        if self._capture_handle is not None:
            self._write_capture(event)
        elif self.config.save_responses:
            self._pending_transport_errors.append(event)

    @abstractmethod
    def generate_frame(self, sequence_number: int) -> CANFrame:
        raise NotImplementedError

    def should_accept_response(self, frame: CANFrame) -> bool:
        return True

    def on_response(self, frame: CANFrame):
        return

    def monitor_response(self, timeout: float = 0.0) -> bool:
        response = self.transport.recv(timeout=timeout)
        if response is None:
            return False
        self.stats.observed_frames += 1
        is_error = bool(response.meta.get("is_error_frame"))
        is_remote = bool(response.meta.get("is_remote_frame"))
        if is_error:
            self.stats.can_error_frames += 1
        elif is_remote:
            self.stats.remote_frames += 1
        else:
            self.stats.ordinary_received += 1
        accepted = not (is_error or is_remote) and self.should_accept_response(response)
        self._write_capture({
            "event": "received", "accepted": accepted,
            "frame_kind": "can_error" if is_error else "remote" if is_remote else "data",
            "frame": PacketLogger._frame_to_json(response),
        })
        if not accepted:
            return True
        try:
            self.logger.record_received(response)
            self.stats.received += 1
            self.on_response(response)
        except Exception:
            self.stats.parse_errors += 1
            logging.getLogger(__name__).exception("Response processing failed")
        return True

    def _poll_responses(self):
        if self.config.save_responses:
            for _ in range(256):
                if not self.monitor_response():
                    break
        elif self.protocol_name in {"uds", "j1939", "cosic"} or self.config.raw_feedback_probability > 0:
            self.monitor_response()

    def on_frame_sent(self, frame: CANFrame):
        return

    def _build_run_summary(self) -> ProtocolRunSummary | None:
        if self._run_started_at is None or self._run_ended_at is None:
            return None

        duration_ms = round((self._run_ended_at - self._run_started_at) * 1000.0, 3)
        return ProtocolRunSummary(
            protocol=self.protocol_name,
            run_id=self.run_id,
            seed=self.config.seed,
            profile_name=self.config.profile_name,
            started_at=self._run_started_at,
            ended_at=self._run_ended_at,
            duration_ms=duration_ms,
            sent=self.stats.sent,
            received=self.stats.received,
            errors=self.stats.parse_errors,
            burst_frames=self._burst_frames_sent,
            transport_errors=self.stats.transport_errors,
            observed_frames=self.stats.observed_frames,
            ordinary_received=self.stats.ordinary_received,
            can_error_frames=self.stats.can_error_frames,
            remote_frames=self.stats.remote_frames,
        )

    def _wait_for_send_slot(self):
        if self.config.rate_mode != 0:
            return

        now = time.monotonic()
        if self._next_send_ts is None:
            self._next_send_ts = now

        sleep_for = self._next_send_ts - now
        if sleep_for > 0:
            time.sleep(sleep_for)

        next_slot = self._next_send_ts + self.RATE_MODE0_INTERVAL_SECONDS
        self._next_send_ts = max(next_slot, time.monotonic())

    def run(self, write_summary: bool = True, write_correlation: bool = True) -> ProtocolRunSummary | None:
        try:
            path = self.config.responses_file
            if self.config.save_responses:
                path = path or Path(f"{self.protocol_name}_responses.jsonl")
                for other in (self.config.replay_file, self.config.save_replay_file,
                              self.config.summary_file, self.config.correlation_report_file):
                    if other is not None and path.resolve() == other.resolve():
                        raise ValueError("responses_file must differ from replay, summary, and correlation paths")
                path.parent.mkdir(parents=True, exist_ok=True)
            capture = path.open("w", encoding="utf-8") if self.config.save_responses and path is not None else nullcontext()
            with capture as handle:
                self._capture_handle = handle
                try:
                    for event in self._pending_transport_errors:
                        self._write_capture(event)
                    self._pending_transport_errors.clear()
                    return self._run(write_summary, write_correlation)
                finally:
                    self.transport.close()
                    self._capture_handle = None
        finally:
            self.transport.close()

    def _run(self, write_summary: bool, write_correlation: bool) -> ProtocolRunSummary | None:
        self._run_started_at = time.time()
        try:
            if self.config.replay_file:
                self.replay(self.config.replay_file)
                return

            if self.config.rate_mode == 0:
                rate = int(1 / self.RATE_MODE0_INTERVAL_SECONDS)
                print(f"[{self.protocol_name}] rate_mode=0 pacing active (~{rate} fps)")

            for i in range(1, self.config.packet_count + 1):
                frame = self.generate_frame(i)
                self._wait_for_send_slot()
                self.transport.send(frame)
                self.logger.record_sent(frame)
                self.stats.sent += 1
                self.on_frame_sent(frame)

                burst_frames: list[CANFrame] = frame.meta.get("burst", [])
                for burst in burst_frames:
                    self._wait_for_send_slot()
                    self.transport.send(burst)
                    self.logger.record_sent(burst)
                    self.stats.sent += 1
                    self._burst_frames_sent += 1
                    self.on_frame_sent(burst)

                self._poll_responses()

                if self.config.print_interval > 0 and i % self.config.print_interval == 0:
                    print(
                        f"[{self.protocol_name}] sent={self.stats.sent} "
                        f"recv={self.stats.received} "
                        f"can_errors={self.stats.can_error_frames} "
                        f"transport_errors={self.stats.transport_errors} "
                        f"live={self.transport.is_live}"
                    )
        except KeyboardInterrupt:
            print("Interrupted by user.")
        finally:
            if self.config.save_responses:
                self._capture_phase = "drain"
                deadline = time.monotonic() + self.config.response_drain_seconds
                while time.monotonic() < deadline:
                    self.monitor_response(timeout=min(0.01, max(0.0, deadline - time.monotonic())))
            self.transport.close()
            self._run_ended_at = time.time()
            if self.config.save_replay_file and self.logger.sent:
                self.logger.save_replay(
                    protocol=self.protocol_name,
                    path=Path(self.config.save_replay_file),
                    note="Saved by CASIC --save-replay",
                    run_id=self.run_id,
                    seed=self.config.seed,
                    profile_name=self.config.profile_name,
                )

            summary = self._build_run_summary()
            if (
                write_summary
                and summary is not None
                and self.config.summary_enabled
                and self.config.summary_file is not None
            ):
                PacketLogger.write_run_summary(Path(self.config.summary_file), [summary])

            if (
                write_correlation
                and self.config.correlation_enabled
                and self.config.correlation_report_file is not None
            ):
                report_path = Path(self.config.correlation_report_file)
                if self.protocol_name in {"uds", "j1939"}:
                    rows = self.logger.build_correlation_rows(
                        protocol=self.protocol_name,
                        run_id=self.run_id,
                        window_seconds=self.config.correlation_window_seconds,
                    )
                    PacketLogger.write_correlation_csv(
                        path=report_path,
                        protocol=self.protocol_name,
                        run_id=self.run_id,
                        rows=rows,
                    )
                else:
                    PacketLogger.write_correlation_csv(
                        path=report_path,
                        protocol=self.protocol_name,
                        run_id=self.run_id,
                        rows=[],
                        unsupported_reason="Protocol does not support request-response correlation",
                    )

        return self._build_run_summary()

    def replay(self, replay_file):
        records = self.logger.load_replay(replay_file)
        for idx, record in enumerate(records, start=1):
            self.transport.send(record.frame)
            self.on_frame_sent(record.frame)
            if self.config.save_responses:
                self._capture_phase = "replay"
                self._poll_responses()
            if self.config.print_interval > 0 and idx % self.config.print_interval == 0:
                print(f"[{self.protocol_name}] replayed={idx}")
