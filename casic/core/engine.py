from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from casic.core.generator import RandomGenerator
from casic.core.logging import PacketLogger
from casic.core.models import CANFrame, FuzzConfig, FuzzStats
from casic.core.transport import CanTransport


class BaseFuzzer(ABC):
    protocol_name = "base"

    def __init__(self, config: FuzzConfig):
        self.config = config
        self.rng = RandomGenerator(seed=config.seed)
        self.logger = PacketLogger()
        self.transport = CanTransport(interface=config.interface)
        self.stats = FuzzStats()

    @abstractmethod
    def generate_frame(self, sequence_number: int) -> CANFrame:
        raise NotImplementedError

    def should_accept_response(self, frame: CANFrame) -> bool:
        return True

    def monitor_response(self):
        response = self.transport.recv(timeout=0.0)
        if response is None:
            return
        if not self.should_accept_response(response):
            return
        self.logger.record_received(response)
        self.stats.received += 1

    def run(self):
        try:
            if self.config.replay_file:
                self.replay(self.config.replay_file)
                return

            for i in range(1, self.config.packet_count + 1):
                frame = self.generate_frame(i)
                self.transport.send(frame)
                self.logger.record_sent(frame)
                self.stats.sent += 1

                burst_frames: list[CANFrame] = frame.meta.get("burst", [])
                for burst in burst_frames:
                    self.transport.send(burst)
                    self.logger.record_sent(burst)
                    self.stats.sent += 1

                if self.protocol_name in {"uds", "j1939"}:
                    self.monitor_response()

                if self.config.print_interval > 0 and i % self.config.print_interval == 0:
                    print(
                        f"[{self.protocol_name}] sent={self.stats.sent} "
                        f"recv={self.stats.received} live={self.transport.is_live}"
                    )
        except KeyboardInterrupt:
            print("Interrupted by user.")
        finally:
            if self.config.save_replay_file and self.logger.sent:
                self.logger.save_replay(
                    protocol=self.protocol_name,
                    path=Path(self.config.save_replay_file),
                    note="Saved by CASIC --save-replay",
                )
            self.transport.close()

    def replay(self, replay_file):
        records = self.logger.load_replay(replay_file)
        for idx, record in enumerate(records, start=1):
            self.transport.send(record.frame)
            if self.config.print_interval > 0 and idx % self.config.print_interval == 0:
                print(f"[{self.protocol_name}] replayed={idx}")
