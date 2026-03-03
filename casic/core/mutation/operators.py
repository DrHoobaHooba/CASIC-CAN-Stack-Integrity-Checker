from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from casic.core.generator import RandomGenerator

MutationMode = Literal[
    "bitflip",
    "nibbleflip",
    "byteflip",
    "boundary",
    "truncate",
    "expand",
    "swap",
    "arithmetic",
    "structured",
    "none",
]


@dataclass(slots=True)
class MutationEngine:
    rng: RandomGenerator

    def mutate_chain(self, payload: bytes, modes: list[str], rate: float = 1.0) -> bytes:
        output = payload
        for mode in modes:
            if self.rng.random() <= rate:
                output = self.mutate(output, mode.strip())
        return output

    def mutate(self, payload: bytes, mode: MutationMode) -> bytes:
        if not payload or mode == "none":
            return payload

        data = bytearray(payload)
        if mode == "bitflip":
            idx = self.rng.randint(0, len(data) - 1)
            bit = 1 << self.rng.randint(0, 7)
            data[idx] ^= bit
            return bytes(data)

        if mode == "nibbleflip":
            idx = self.rng.randint(0, len(data) - 1)
            if self.rng.random() < 0.5:
                data[idx] ^= 0x0F
            else:
                data[idx] ^= 0xF0
            return bytes(data)

        if mode == "byteflip":
            idx = self.rng.randint(0, len(data) - 1)
            data[idx] ^= 0xFF
            return bytes(data)

        if mode == "boundary":
            idx = self.rng.randint(0, len(data) - 1)
            data[idx] = self.rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF])
            return bytes(data)

        if mode == "truncate" and len(data) > 1:
            new_len = self.rng.randint(1, len(data) - 1)
            return bytes(data[:new_len])

        if mode == "expand":
            extra = self.rng.randint(1, 8)
            data.extend(self.rng.randbytes(extra))
            return bytes(data)

        if mode == "swap" and len(data) > 2:
            i = self.rng.randint(0, len(data) - 1)
            j = self.rng.randint(0, len(data) - 1)
            data[i], data[j] = data[j], data[i]
            return bytes(data)

        if mode == "arithmetic":
            idx = self.rng.randint(0, len(data) - 1)
            delta = self.rng.choice([1, 2, 4, 8, 16])
            if self.rng.random() < 0.5:
                data[idx] = (data[idx] + delta) & 0xFF
            else:
                data[idx] = (data[idx] - delta) & 0xFF
            return bytes(data)

        if mode == "structured":
            idx = self.rng.randint(0, len(data) - 1)
            data[idx] = self.rng.choice([0x00, 0x7F, 0x80, 0xFF])
            if len(data) > 2 and self.rng.random() < 0.4:
                data[0], data[-1] = data[-1], data[0]
            return bytes(data)

        return payload
