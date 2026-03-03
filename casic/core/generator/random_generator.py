from __future__ import annotations

import random


class RandomGenerator:
    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)

    def can_id(self, extended: bool = False) -> int:
        if extended:
            return self._rng.randint(0, 0x1FFFFFFF)
        return self._rng.randint(0, 0x7FF)

    def uds_sid(self) -> int:
        return self._rng.randint(0, 0xFF)

    def j1939_pgn(self) -> int:
        return self._rng.randint(0, 0x3FFFF)

    def j1939_address(self) -> int:
        return self._rng.randint(0x00, 0xFE)

    def choice(self, values: list[int] | list[str]):
        return self._rng.choice(values)

    def randbytes(self, size: int) -> bytes:
        return bytes(self._rng.randint(0, 255) for _ in range(size))

    def randint(self, minimum: int, maximum: int) -> int:
        return self._rng.randint(minimum, maximum)

    def random(self) -> float:
        return self._rng.random()
