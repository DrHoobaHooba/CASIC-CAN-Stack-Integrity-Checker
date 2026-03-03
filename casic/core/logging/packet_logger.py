from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from casic.core.models import CANFrame, ReplayRecord


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

    def save_replay(self, protocol: str, path: Path, note: str = ""):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for frame in self.sent:
                record = ReplayRecord(protocol=protocol, frame=frame, note=note)
                data = asdict(record)
                data["frame"]["data"] = frame.data.hex()
                handle.write(json.dumps(data) + "\n")

    def load_replay(self, path: Path) -> list[ReplayRecord]:
        entries: list[ReplayRecord] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                raw = json.loads(line)
                frame_data = raw["frame"]
                frame = CANFrame(
                    can_id=int(frame_data["can_id"]),
                    data=bytes.fromhex(frame_data["data"]),
                    is_extended_id=bool(frame_data.get("is_extended_id", False)),
                    is_fd=bool(frame_data.get("is_fd", False)),
                    timestamp=frame_data.get("timestamp"),
                    meta=frame_data.get("meta", {}),
                )
                entries.append(
                    ReplayRecord(
                        protocol=raw["protocol"],
                        frame=frame,
                        note=raw.get("note", ""),
                    )
                )
        return entries
