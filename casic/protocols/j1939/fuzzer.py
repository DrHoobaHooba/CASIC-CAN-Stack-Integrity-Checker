from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame


class J1939Fuzzer(BaseFuzzer):
    protocol_name = "j1939"

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

        return CANFrame(
            can_id=self._build_can_id(priority, tp_cm_pgn, sa),
            data=cm_data,
            is_extended_id=True,
            meta={"burst": burst_frames},
        )

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
