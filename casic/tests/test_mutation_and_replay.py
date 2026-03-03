from pathlib import Path

from casic.core.generator import RandomGenerator
from casic.core.logging import PacketLogger
from casic.core.models import CANFrame
from casic.core.mutation import MutationEngine


def test_mutation_changes_payload():
    rng = RandomGenerator(seed=1)
    mutator = MutationEngine(rng=rng)
    source = bytes([0xAA] * 8)
    mutated = mutator.mutate(source, "bitflip")
    assert mutated != source


def test_replay_roundtrip(tmp_path: Path):
    logger = PacketLogger()
    frame = CANFrame(can_id=0x123, data=b"\x01\x02\x03\x04")
    logger.record_sent(frame)
    replay_file = tmp_path / "r.jsonl"
    logger.save_replay("cansic", replay_file, note="test")

    loaded = logger.load_replay(replay_file)
    assert len(loaded) == 1
    assert loaded[0].frame.can_id == 0x123
    assert loaded[0].frame.data == b"\x01\x02\x03\x04"
