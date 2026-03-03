from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from casic.core.models import CANFrame

try:
    import can  # type: ignore
except Exception:  # pragma: no cover
    can = None


@dataclass(slots=True)
class CanTransport:
    interface: str
    bitrate: int = 500000
    _bus: Any = None

    def _resolve_backend(self) -> tuple[str, str]:
        channel = self.interface
        if ":" in channel:
            prefix, value = channel.split(":", 1)
            lowered = prefix.strip().lower()
            if lowered in {"pcan", "socketcan"}:
                return lowered, value.strip()

        normalized = channel.strip().upper()
        if normalized.startswith("PCAN_") or "USBBUS" in normalized:
            return "pcan", channel

        if os.name == "nt":
            return "pcan", channel
        return "socketcan", channel

    def __post_init__(self):
        self._bus = None
        if can is not None:
            try:
                backend, channel = self._resolve_backend()
                bus_kwargs: dict[str, Any] = {"channel": channel, "interface": backend}
                if backend == "pcan":
                    bus_kwargs["bitrate"] = self.bitrate
                self._bus = can.interface.Bus(**bus_kwargs)
            except Exception:
                self._bus = None

    @property
    def is_live(self) -> bool:
        return self._bus is not None

    def send(self, frame: CANFrame):
        if self._bus is None:
            return
        msg = can.Message(  # type: ignore[attr-defined]
            arbitration_id=frame.can_id,
            data=frame.data,
            is_extended_id=frame.is_extended_id,
            is_fd=frame.is_fd,
        )
        try:
            self._bus.send(msg)
        except Exception as exc:
            error_text = str(exc).lower()
            if "queue is full" in error_text or "tx queue" in error_text:
                return
            return

    def recv(self, timeout: float = 0.0) -> CANFrame | None:
        if self._bus is None:
            return None
        msg = self._bus.recv(timeout=timeout)
        if msg is None:
            return None
        return CANFrame(
            can_id=msg.arbitration_id,
            data=bytes(msg.data),
            is_extended_id=msg.is_extended_id,
            is_fd=msg.is_fd,
            timestamp=msg.timestamp,
        )

    def close(self):
        if self._bus is not None:
            self._bus.shutdown()
