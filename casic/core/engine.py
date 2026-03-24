from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path

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
        self.transport = CanTransport(interface=config.interface)
        self.stats = FuzzStats()
        self._next_send_ts: float | None = None
        self._run_started_at: float | None = None
        self._run_ended_at: float | None = None
        self._burst_frames_sent: int = 0
        self.run_id = PacketLogger.deterministic_run_id(self.protocol_name, self.config)

    @abstractmethod
    def generate_frame(self, sequence_number: int) -> CANFrame:
        raise NotImplementedError

    def should_accept_response(self, frame: CANFrame) -> bool:
        return True

    def on_response(self, frame: CANFrame):
        return

    def monitor_response(self):
        try:
            response = self.transport.recv(timeout=0.0)
            if response is None:
                return
            if not self.should_accept_response(response):
                return
            self.logger.record_received(response)
            self.stats.received += 1
            self.on_response(response)
        except Exception:
            self.stats.parse_errors += 1

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

                burst_frames: list[CANFrame] = frame.meta.get("burst", [])
                for burst in burst_frames:
                    self._wait_for_send_slot()
                    self.transport.send(burst)
                    self.logger.record_sent(burst)
                    self.stats.sent += 1
                    self._burst_frames_sent += 1

                if self.protocol_name in {"uds", "j1939", "cosic"}:
                    self.monitor_response()

                if self.config.print_interval > 0 and i % self.config.print_interval == 0:
                    print(
                        f"[{self.protocol_name}] sent={self.stats.sent} "
                        f"recv={self.stats.received} live={self.transport.is_live}"
                    )
        except KeyboardInterrupt:
            print("Interrupted by user.")
        finally:
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
            self.transport.close()

        return self._build_run_summary()

    def replay(self, replay_file):
        records = self.logger.load_replay(replay_file)
        for idx, record in enumerate(records, start=1):
            self.transport.send(record.frame)
            if self.config.print_interval > 0 and idx % self.config.print_interval == 0:
                print(f"[{self.protocol_name}] replayed={idx}")
