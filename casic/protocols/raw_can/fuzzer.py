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
        self._observed_templates: dict[tuple[int, bool, bool], bytes] = {}

    def on_response(self, frame: CANFrame):
        if self.config.raw_feedback_probability <= 0:
            return
        if frame.meta.get("is_error_frame") or frame.meta.get("is_remote_frame"):
            return
        if self.config.destination != "rand" and frame.can_id != int(self.config.destination, 0):
            return
        if frame.is_fd and not (self.can_fd or self.config.raw_fd_probability > 0):
            return
        key = (frame.can_id, frame.is_extended_id, frame.is_fd)
        if key not in self._observed_templates and len(self._observed_templates) >= 256:
            del self._observed_templates[next(iter(self._observed_templates))]
        self._observed_templates[key] = bytes(frame.data)

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
        feedback = False
        if self._observed_templates and self.config.raw_feedback_probability > 0 and self.rng.random() < self.config.raw_feedback_probability:
            key = self.rng.choice(list(self._observed_templates))
            can_id, is_extended, use_fd = key
            payload = self._observed_templates[key]
            minimum = self.config.payload_min_len or 0
            maximum = self.config.payload_max_len if self.config.payload_max_len is not None else (64 if use_fd else 8)
            maximum = min(maximum, 64 if use_fd else 8)
            payload = payload[:maximum]
            if len(payload) < minimum:
                payload += self.rng.randbytes(minimum - len(payload))
            feedback = True
        if self.config.mutation_chain:
            chain = [part.strip() for part in self.config.mutation_chain.split(",") if part.strip()]
            payload = self.mutator.mutate_chain(payload, chain, rate=self.config.mutation_rate)
        else:
            payload = self.mutator.mutate(payload, self.mutation_mode)

        frame = CANFrame(can_id=can_id, data=payload, is_extended_id=is_extended, is_fd=use_fd)
        if feedback:
            frame.meta["feedback"] = "observed-traffic-template"
        if self.rng.random() < self.config.raw_error_injection_probability:
            frame.meta["error_frame_requested"] = True
        return frame
