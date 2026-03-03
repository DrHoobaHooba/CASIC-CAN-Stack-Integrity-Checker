from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame


class J1939Fuzzer(BaseFuzzer):
    protocol_name = "j1939"

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
        can_id = (priority << 26) | (pgn << 8) | sa
        payload = self.rng.randbytes(8)
        payload = bytes([da]) + payload[1:]

        if self.rng.random() < self.config.j1939_tp_probability:
            payload = bytes([0x20, self.rng.randint(0, 255)]) + payload[2:]
            if self.rng.random() < 0.5:
                pgn = self.rng.choice([0xEC00, 0xEB00])
                can_id = (priority << 26) | (pgn << 8) | sa

        return CANFrame(can_id=can_id, data=payload, is_extended_id=True)
