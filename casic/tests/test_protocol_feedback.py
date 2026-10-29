import pytest

from casic.core.models import CANFrame, CANopenDictionary, DictionaryEntry, FuzzConfig
from casic.core.transport import socketcan
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer


@pytest.fixture(autouse=True)
def no_hardware(monkeypatch):
    monkeypatch.setattr(socketcan, "can", None)


def config(**overrides):
    values = dict(interface="unused", rate_mode=1, source_mode="rand",
                  destination="rand", packet_count=1, print_interval=0, seed=7)
    values.update(overrides)
    return FuzzConfig(**values)


def test_raw_feedback_mutates_observed_template(monkeypatch):
    fuzzer = RawCANFuzzer(config(raw_feedback_probability=1), mutation_mode="none")
    fuzzer.on_response(CANFrame(0x456, b"\x12\x34"))
    frame = fuzzer.generate_frame(1)
    assert frame.can_id == 0x456 and frame.data == b"\x12\x34"
    assert frame.meta["feedback"] == "observed-traffic-template"


def test_raw_feedback_respects_destination_fd_and_bounds():
    fuzzer = RawCANFuzzer(config(raw_feedback_probability=1, destination="0x456",
                                payload_min_len=3, payload_max_len=4), mutation_mode="none")
    fuzzer.on_response(CANFrame(0x123, b"\x01"))
    fuzzer.on_response(CANFrame(0x456, b"\x01", is_fd=True))
    assert not fuzzer._observed_templates
    fuzzer.on_response(CANFrame(0x456, b"\x01"))
    assert len(fuzzer.generate_frame(1).data) == 3


def test_raw_feedback_cache_is_bounded():
    fuzzer = RawCANFuzzer(config(raw_feedback_probability=1))
    for can_id in range(300):
        fuzzer.on_response(CANFrame(can_id, b""))
    assert len(fuzzer._observed_templates) == 256


@pytest.mark.parametrize("fuzzer_class,feedback", [
    (RawCANFuzzer, CANFrame(0x123, b"\x01")),
    (CANopenFuzzer, CANFrame(0x70A, b"\x05")),
    (J1939Fuzzer, CANFrame(0x18E88090, bytes(8), is_extended_id=True)),
])
def test_feedback_disabled_preserves_seeded_generation(fuzzer_class, feedback):
    first = fuzzer_class(config(node_id=10))
    second = fuzzer_class(config(node_id=10))
    first.on_response(feedback)
    for sequence in range(1, 15):
        a = first.generate_frame(sequence)
        b = second.generate_frame(sequence)
        assert (a.can_id, a.data, a.is_extended_id, a.meta) == (b.can_id, b.data, b.is_extended_id, b.meta)


@pytest.mark.parametrize("state,expected_id", [(0, 0), (4, 0), (5, 0x60A), (127, 0x60A)])
def test_canopen_heartbeat_guides_next_generation(state, expected_id):
    fuzzer = CANopenFuzzer(config(node_id=10, canopen_feedback_probability=1))
    heartbeat = CANFrame(0x70A, bytes([state]))
    assert fuzzer.should_accept_response(heartbeat)
    assert not fuzzer.should_accept_response(CANFrame(0x70B, bytes([state])))
    fuzzer.on_response(heartbeat)
    frame = fuzzer.generate_frame(1)
    assert frame.can_id == expected_id
    assert "feedback" in frame.meta
    if expected_id == 0:
        assert frame.data == b"\x80\x0a"


def test_canopen_feedback_uses_existing_abort_blacklist():
    dictionary = CANopenDictionary(entries=[
        DictionaryEntry(0x2000, 0, "one", "0x0007", "ro"),
        DictionaryEntry(0x2001, 0, "two", "0x0007", "ro"),
    ])
    fuzzer = CANopenFuzzer(config(node_id=10, canopen_feedback_probability=1), dictionary)
    fuzzer.on_response(CANFrame(0x58A, bytes.fromhex("8000200000000206")))
    assert (0x2000, 0) in fuzzer._abort_blacklist
    assert fuzzer._random_dictionary_entry().index == 0x2001


def track_rts(fuzzer, pgn=0xF004):
    fuzzer.on_frame_sent(CANFrame(0x18EC9080,
                                 bytes.fromhex("1009000210") + pgn.to_bytes(3, "little"),
                                 is_extended_id=True))


@pytest.mark.parametrize("kind", ["ack", "negative-ack", "tp-abort"])
def test_j1939_feedback_requires_matching_peer_destination_and_pgn(kind):
    fuzzer = J1939Fuzzer(config(j1939_feedback_probability=1, j1939_sa=0x80,
                                j1939_da=0x90, j1939_tp_probability=1))
    track_rts(fuzzer)
    control = {"ack": 0, "negative-ack": 1, "tp-abort": 0xFF}[kind]
    pf = 0xEC if kind == "tp-abort" else 0xE8
    payload = bytes([control]) + bytes(4) + (0xF004).to_bytes(3, "little")
    for bad_id, bad_payload in [
        ((6 << 26) | (pf << 16) | (0x80 << 8) | 0x91, payload),
        ((6 << 26) | (pf << 16) | (0x81 << 8) | 0x90, payload),
        ((6 << 26) | (pf << 16) | (0x80 << 8) | 0x90, payload[:5] + bytes(3)),
    ]:
        fuzzer.on_response(CANFrame(bad_id, bad_payload, is_extended_id=True))
        assert fuzzer._feedback is None
    fuzzer.on_response(CANFrame((6 << 26) | (pf << 16) | (0x80 << 8) | 0x90,
                                payload, is_extended_id=True))
    frame = fuzzer.generate_frame(1)
    assert frame.meta["feedback"] == kind
    if kind != "ack":
        assert "burst" not in frame.meta
    assert fuzzer._feedback is None


def test_j1939_feedback_preserves_explicit_pgn():
    fuzzer = J1939Fuzzer(config(j1939_feedback_probability=1, j1939_sa=0x80,
                                j1939_da=0x90, j1939_pgn=0xF004, j1939_tp_probability=0))
    track_rts(fuzzer)
    fuzzer.on_response(CANFrame(0x18E88090, bytes.fromhex("010000000004f000"), is_extended_id=True))
    frame = fuzzer.generate_frame(1)
    assert (frame.can_id >> 8) & 0x3FFFF == 0xF004


@pytest.mark.parametrize("pgn", [0xEF00, 0xF004])
def test_j1939_positive_ack_biases_actual_pgn_and_peer(pgn):
    fuzzer = J1939Fuzzer(config(j1939_feedback_probability=1, j1939_sa=0x80,
                                j1939_tp_probability=0))
    track_rts(fuzzer, pgn)
    fuzzer.on_response(CANFrame(0x18E88090, bytes(5) + pgn.to_bytes(3, "little"),
                                is_extended_id=True))
    frame = fuzzer.generate_frame(1)
    wire_pgn = (frame.can_id >> 8) & 0x3FFFF
    expected = pgn | 0x90 if pgn == 0xEF00 else pgn
    assert wire_pgn == expected


def test_j1939_feedback_keeps_tp_pdu1_pgn_canonical():
    fuzzer = J1939Fuzzer(config(j1939_feedback_probability=1, j1939_sa=0x80,
                                j1939_da=0x90, j1939_tp_probability=1))
    track_rts(fuzzer, 0xEF00)
    fuzzer.on_response(CANFrame(0x18E88090, bytes(5) + (0xEF00).to_bytes(3, "little"),
                                is_extended_id=True))
    frame = fuzzer.generate_frame(1)
    assert int.from_bytes(frame.data[5:8], "little") == 0xEF00


def test_j1939_rejects_stale_feedback():
    fuzzer = J1939Fuzzer(config(j1939_feedback_probability=1))
    track_rts(fuzzer)
    fuzzer._feedback_sent_at -= 3
    fuzzer.on_response(CANFrame(0x18E88090, bytes.fromhex("000000000004f000"),
                                is_extended_id=True))
    assert fuzzer._feedback is None


@pytest.mark.parametrize("meta", [{"is_error_frame": True}, {"is_remote_frame": True}])
def test_raw_feedback_does_not_learn_error_or_remote_frames(meta):
    fuzzer = RawCANFuzzer(config(raw_feedback_probability=1))
    fuzzer.on_response(CANFrame(0x123, b"", meta=meta))
    assert not fuzzer._observed_templates
