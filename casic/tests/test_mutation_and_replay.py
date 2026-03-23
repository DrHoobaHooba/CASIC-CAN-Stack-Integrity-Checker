from pathlib import Path
import json

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


def test_replay_enrichment_fields_are_written(tmp_path: Path):
    logger = PacketLogger()
    logger.record_sent(CANFrame(can_id=0x321, data=b"\xAA\xBB"))
    replay_file = tmp_path / "enriched.jsonl"

    logger.save_replay(
        protocol="uds",
        path=replay_file,
        note="enriched",
        run_id="abcd1234",
        seed=99,
        profile_name="ci-profile",
    )

    raw = json.loads(replay_file.read_text(encoding="utf-8").strip())
    assert raw["run_id"] == "abcd1234"
    assert raw["seed"] == 99
    assert raw["profile_name"] == "ci-profile"

    loaded = logger.load_replay(replay_file)
    assert loaded[0].run_id == "abcd1234"
    assert loaded[0].seed == 99
    assert loaded[0].profile_name == "ci-profile"


def test_load_replay_accepts_legacy_jsonl_without_metadata(tmp_path: Path):
    replay_file = tmp_path / "legacy.jsonl"
    replay_file.write_text(
        json.dumps(
            {
                "protocol": "cansic",
                "frame": {
                    "can_id": 291,
                    "data": "01020304",
                    "is_extended_id": False,
                    "is_fd": False,
                },
                "note": "legacy",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    loaded = PacketLogger().load_replay(replay_file)

    assert len(loaded) == 1
    assert loaded[0].run_id is None
    assert loaded[0].seed is None
    assert loaded[0].profile_name is None
    assert loaded[0].frame.can_id == 291
