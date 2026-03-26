from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame


class J1939Fuzzer(BaseFuzzer):
    protocol_name = "j1939"

    def __init__(self, config):
        super().__init__(config)
        self._tp_fault_epoch = 0

    def _with_sequence(self, frame: CANFrame, sequence: int) -> CANFrame:
        payload = bytes([sequence & 0xFF]) + frame.data[1:]
        return CANFrame(
            can_id=frame.can_id,
            data=payload,
            is_extended_id=frame.is_extended_id,
            is_fd=frame.is_fd,
            timestamp=frame.timestamp,
            meta=dict(frame.meta),
        )

    def _apply_tp_sequence_anomaly(self, burst_frames: list[CANFrame]) -> str | None:
        if len(burst_frames) < 2:
            return None
        if self.rng.random() >= self.config.j1939_tp_sequence_anomaly_probability:
            return None

        anomaly = self.rng.choice(["gap", "duplicate", "reorder"])

        if anomaly == "gap":
            index = self.rng.randint(1, len(burst_frames) - 1)
            current_seq = burst_frames[index].data[0]
            burst_frames[index] = self._with_sequence(burst_frames[index], (current_seq + 1) & 0xFF)
            return "gap"

        if anomaly == "duplicate":
            index = self.rng.randint(1, len(burst_frames) - 1)
            previous_seq = burst_frames[index - 1].data[0]
            burst_frames[index] = self._with_sequence(burst_frames[index], previous_seq)
            return "duplicate"

        if len(burst_frames) < 3:
            index = self.rng.randint(1, len(burst_frames) - 1)
            previous_seq = burst_frames[index - 1].data[0]
            burst_frames[index] = self._with_sequence(burst_frames[index], previous_seq)
            return "duplicate"
        left = self.rng.randint(1, len(burst_frames) - 2)
        right = self.rng.randint(left + 1, len(burst_frames) - 1)
        burst_frames[left], burst_frames[right] = burst_frames[right], burst_frames[left]
        return "reorder"

    def _apply_incomplete_dt_sequence(self, burst_frames: list[CANFrame]) -> str | None:
        if len(burst_frames) < 2:
            return None
        if self.rng.random() >= self.config.j1939_tp_incomplete_dt_probability:
            return None
        remove_count = self.rng.randint(1, max(1, len(burst_frames) // 2))
        del burst_frames[-remove_count:]
        return f"missing-tail-{remove_count}"

    def _apply_packet_count_mismatch(self, cm_data: bytes, actual_count: int) -> tuple[bytes, str | None]:
        if self.rng.random() >= self.config.j1939_tp_packet_count_mismatch_probability:
            return cm_data, None

        advertised = actual_count + self.rng.choice([-2, -1, 1, 2])
        if advertised <= 0 or advertised == actual_count:
            advertised = max(1, actual_count + 1)
        mutated = bytearray(cm_data)
        mutated[3] = advertised & 0xFF
        return bytes(mutated), f"advertised:{advertised}|actual:{actual_count}"

    def _apply_cm_dt_order_fault(
        self,
        cm_frame: CANFrame,
        burst_frames: list[CANFrame],
    ) -> tuple[CANFrame, str | None]:
        if not burst_frames:
            return cm_frame, None
        if self.rng.random() >= self.config.j1939_tp_cm_dt_order_fault_probability:
            return cm_frame, None

        self._tp_fault_epoch += 1
        fault = self.rng.choice(["dt-before-cm", "cm-mid-stream"])
        if fault == "dt-before-cm":
            first_dt = burst_frames.pop(0)
            reordered = [cm_frame, *burst_frames]
            return CANFrame(
                can_id=first_dt.can_id,
                data=first_dt.data,
                is_extended_id=first_dt.is_extended_id,
                is_fd=first_dt.is_fd,
                timestamp=first_dt.timestamp,
                meta={"burst": reordered, "tp_fault_epoch": self._tp_fault_epoch},
            ), fault

        split = min(1, len(burst_frames) - 1)
        leading_dt = burst_frames[: split + 1]
        trailing_dt = burst_frames[split + 1 :]
        head = leading_dt[0]
        reordered = [*leading_dt[1:], cm_frame, *trailing_dt]
        return CANFrame(
            can_id=head.can_id,
            data=head.data,
            is_extended_id=head.is_extended_id,
            is_fd=head.is_fd,
            timestamp=head.timestamp,
            meta={"burst": reordered, "tp_fault_epoch": self._tp_fault_epoch},
        ), fault

    def _build_can_id(self, priority: int, pgn: int, sa: int) -> int:
        return (priority << 26) | (pgn << 8) | sa

    def _build_tp_burst(
        self,
        priority: int,
        sa: int,
        da: int,
        app_pgn: int,
    ) -> CANFrame:
        app_len = self.rng.randint(9, 64)
        app_payload = self.rng.randbytes(app_len)
        packet_count = (app_len + 6) // 7

        use_bam = da == 0xFF or self.rng.random() < 0.5
        tp_cm_pgn = 0xEC00 | (0xFF if use_bam else da)
        tp_dt_pgn = 0xEB00 | (0xFF if use_bam else da)

        pgn_lsb = app_pgn & 0xFF
        pgn_mid = (app_pgn >> 8) & 0xFF
        pgn_msb = (app_pgn >> 16) & 0xFF

        if use_bam:
            cm_data = bytes([0x20, app_len & 0xFF, (app_len >> 8) & 0xFF, packet_count, 0xFF, pgn_lsb, pgn_mid, pgn_msb])
        else:
            cm_data = bytes([0x10, app_len & 0xFF, (app_len >> 8) & 0xFF, packet_count, 0x10, pgn_lsb, pgn_mid, pgn_msb])

        burst_frames: list[CANFrame] = []
        sequence = 1
        remaining = app_payload
        while remaining:
            chunk, remaining = remaining[:7], remaining[7:]
            dt_data = bytes([sequence]) + chunk
            burst_frames.append(
                CANFrame(
                    can_id=self._build_can_id(priority, tp_dt_pgn, sa),
                    data=dt_data.ljust(8, b"\xFF"),
                    is_extended_id=True,
                )
            )
            sequence += 1

        incomplete = self._apply_incomplete_dt_sequence(burst_frames)
        anomaly = self._apply_tp_sequence_anomaly(burst_frames)
        actual_packet_count = len(burst_frames)
        cm_data, packet_count_mismatch = self._apply_packet_count_mismatch(cm_data, actual_packet_count)
        timing_fault_ms: int | None = None
        if self.rng.random() < self.config.j1939_tp_timing_fault_probability:
            timing_fault_ms = self.rng.choice([25, 50, 100, 250])

        cm_frame = CANFrame(
            can_id=self._build_can_id(priority, tp_cm_pgn, sa),
            data=cm_data,
            is_extended_id=True,
        )
        head_frame, order_fault = self._apply_cm_dt_order_fault(cm_frame, burst_frames)
        head_frame.meta.update(
            {
                "burst": head_frame.meta.get("burst", burst_frames),
                "tp_sequence_anomaly": anomaly,
                "tp_incomplete_dt": incomplete,
                "tp_packet_count_mismatch": packet_count_mismatch,
                "tp_cm_dt_order_fault": order_fault,
                "tp_timing_fault_ms": timing_fault_ms,
            }
        )
        return head_frame

    def generate_frame(self, sequence_number: int) -> CANFrame:
        priority = self.config.j1939_priority if self.config.j1939_priority is not None else self.rng.randint(0, 7)
        pgn = self.config.j1939_pgn if self.config.j1939_pgn is not None else self.rng.j1939_pgn()
        if self.rng.random() < self.config.j1939_invalid_pgn_probability:
            pgn = self.rng.choice([0x00000, 0x3FFFF, 0x0FFFF, 0x30000])
        sa = self.config.j1939_sa if self.config.j1939_sa is not None else self.rng.j1939_address()
        if self.config.j1939_da is not None:
            da = self.config.j1939_da
        elif self.config.destination != "rand":
            da = int(self.config.destination, 0) & 0xFF
        else:
            da = self.rng.j1939_address()
        can_id = self._build_can_id(priority, pgn, sa)
        payload = self.rng.randbytes(8)
        payload = bytes([da]) + payload[1:]

        if self.rng.random() < self.config.j1939_tp_probability:
            return self._build_tp_burst(priority=priority, sa=sa, da=da, app_pgn=pgn)

        return CANFrame(can_id=can_id, data=payload, is_extended_id=True)
