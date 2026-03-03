from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame
from casic.core.mutation import MutationEngine


class RawCANFuzzer(BaseFuzzer):
    protocol_name = "cansic"

    def __init__(self, config, can_fd: bool = False, mutation_mode: str = "bitflip"):
        super().__init__(config)
        self.can_fd = can_fd
        self.mutator = MutationEngine(rng=self.rng)
        self.mutation_mode = config.mutation_mode or mutation_mode

    def _payload_size(self, is_fd: bool) -> int:
        minimum = self.config.payload_min_len if self.config.payload_min_len is not None else (0 if is_fd else 8)
        default_max = 64 if is_fd else 8
        maximum = self.config.payload_max_len if self.config.payload_max_len is not None else default_max
        minimum = max(0, minimum)
        maximum = max(minimum, min(default_max, maximum))
        return self.rng.randint(minimum, maximum)

    def generate_frame(self, sequence_number: int) -> CANFrame:
        is_extended = self.rng.random() < self.config.raw_extended_id_probability
        can_id = self.rng.can_id(extended=is_extended) if self.config.destination == "rand" else int(self.config.destination, 0)
        use_fd = self.can_fd or (self.rng.random() < self.config.raw_fd_probability)
        payload_size = self._payload_size(use_fd)
        payload = self.rng.randbytes(payload_size)
        if self.config.mutation_chain:
            chain = [part.strip() for part in self.config.mutation_chain.split(",") if part.strip()]
            payload = self.mutator.mutate_chain(payload, chain, rate=self.config.mutation_rate)
        else:
            payload = self.mutator.mutate(payload, self.mutation_mode)

        frame = CANFrame(can_id=can_id, data=payload, is_extended_id=is_extended, is_fd=use_fd)
        if self.rng.random() < self.config.raw_error_injection_probability:
            frame.meta["error_frame_requested"] = True
        return frame
