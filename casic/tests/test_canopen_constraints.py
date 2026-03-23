from __future__ import annotations

from casic.core.models import CANopenDictionary, DictionaryEntry, FuzzConfig
from casic.protocols.canopen import CANopenFuzzer


def _build_config() -> FuzzConfig:
    return FuzzConfig(
        interface="can0",
        rate_mode=1,
        source_mode="rand",
        destination="rand",
        packet_count=1,
        print_interval=0,
        seed=11,
        node_id=5,
        canopen_invalid_sdo_probability=0.0,
    )


def test_sdo_read_only_entry_uses_upload_command():
    dictionary = CANopenDictionary(
        entries=[
            DictionaryEntry(
                index=0x2001,
                subindex=0x00,
                name="ro-entry",
                data_type="0x0006",
                access_type="ro",
                low_limit="0",
                high_limit="65535",
                pdo_mapping=True,
            )
        ]
    )
    fuzzer = CANopenFuzzer(_build_config(), dictionary=dictionary)

    frame = fuzzer._generate_sdo()

    assert frame.data[0] == 0x40
    assert frame.data[1] == 0x01
    assert frame.data[2] == 0x20
    assert frame.data[3] == 0x00


def test_sdo_write_only_entry_value_respects_limits():
    dictionary = CANopenDictionary(
        entries=[
            DictionaryEntry(
                index=0x2002,
                subindex=0x00,
                name="wo-entry",
                data_type="0x0006",
                access_type="wo",
                low_limit="10",
                high_limit="20",
                pdo_mapping=True,
            )
        ]
    )
    fuzzer = CANopenFuzzer(_build_config(), dictionary=dictionary)

    frame = fuzzer._generate_sdo()

    assert frame.data[0] in {0x2F, 0x2B, 0x23}
    value = int.from_bytes(frame.data[4:8], byteorder="little", signed=False)
    assert 10 <= value <= 20


def test_pdo_mapping_uses_dictionary_sizes_and_padding():
    dictionary = CANopenDictionary(
        entries=[
            DictionaryEntry(
                index=0x3000,
                subindex=0x00,
                name="u16",
                data_type="0x0006",
                access_type="rw",
                pdo_mapping=True,
            ),
            DictionaryEntry(
                index=0x3001,
                subindex=0x00,
                name="u8",
                data_type="0x0005",
                access_type="rw",
                pdo_mapping=True,
            ),
        ],
        pdo_mappings={"TPDO1": [(0x3000, 0x00), (0x3001, 0x00)]},
    )
    fuzzer = CANopenFuzzer(_build_config(), dictionary=dictionary)

    frame = fuzzer._generate_pdo()

    assert len(frame.data) == 8
    assert frame.data[3:] == b"\x00" * 5
