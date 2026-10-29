from __future__ import annotations

import os
import logging
import time
from collections.abc import Callable
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
    on_error: Callable[[dict[str, Any]], None] | None = None

    def _report_error(self, operation: str, exc: Exception, frame: CANFrame | None = None):
        logging.getLogger(__name__).error("CAN %s failed on %s: %s: %s", operation, self.interface, type(exc).__name__, exc)
        if self.on_error is not None:
            self.on_error({
                "operation": operation, "interface": self.interface,
                "timestamp": time.time(), "error_type": type(exc).__name__,
                "message": str(exc), "frame": frame,
            })

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
            except Exception as exc:
                self._bus = None
                self._report_error("open", exc)
        else:
            self._report_error("open", RuntimeError("python-can is unavailable; transport is offline"))

    @property
    def is_live(self) -> bool:
        return self._bus is not None

    def send(self, frame: CANFrame):
        if self._bus is None:
            return
        try:
            msg = can.Message(  # type: ignore[attr-defined]
                arbitration_id=frame.can_id,
                data=frame.data,
                is_extended_id=frame.is_extended_id,
                is_fd=frame.is_fd,
            )
            self._bus.send(msg)
        except Exception as exc:
            self._report_error("send", exc, frame)

    def recv(self, timeout: float = 0.0) -> CANFrame | None:
        if self._bus is None:
            return None
        try:
            msg = self._bus.recv(timeout=timeout)
        except Exception as exc:
            self._report_error("receive", exc)
            return None
        if msg is None:
            return None
        return CANFrame(
            can_id=msg.arbitration_id,
            data=bytes(msg.data),
            is_extended_id=msg.is_extended_id,
            is_fd=msg.is_fd,
            timestamp=time.time(),
            meta={
                "adapter_timestamp": msg.timestamp,
                "timestamp_source": "host_receive",
                "is_error_frame": getattr(msg, "is_error_frame", False),
                "is_remote_frame": getattr(msg, "is_remote_frame", False),
                "is_rx": getattr(msg, "is_rx", True),
                "dlc": getattr(msg, "dlc", len(msg.data)),
            },
        )

    def close(self):
        if self._bus is not None:
            try:
                self._bus.shutdown()
            except Exception as exc:
                self._report_error("close", exc)
            finally:
                self._bus = None
