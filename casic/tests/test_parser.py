from pathlib import Path

from casic.core.parser import CANopenDictionaryParser


def test_load_eds():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/canopen/node.eds"))
    assert len(dictionary.entries) >= 2
    assert dictionary.cob_ids["SDO_RX"] == 0x600


def test_load_eds_extracts_array_sizes(tmp_path: Path):
    eds = tmp_path / "array.eds"
    eds.write_text(
        """
[2002sub0]
ParameterName=ArrayCount
DataType=0x0005
AccessType=ro
DefaultValue=3

[2002sub1]
ParameterName=ArrayEntry1
DataType=0x0005
AccessType=rw
""".strip(),
        encoding="utf-8",
    )

    parser = CANopenDictionaryParser()
    dictionary = parser.load(eds)

    assert dictionary.array_sizes[0x2002] == 3


def test_load_xdd():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/canopen/drive.xdd"))
    assert len(dictionary.entries) >= 2
    assert "TPDO1" in dictionary.cob_ids


def test_load_xdc():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/canopen/module.xdc"))
    assert len(dictionary.entries) >= 2
    assert dictionary.cob_ids["RPDO1"] == 0x200


def test_eds_parser_preserves_access_limits_and_pdo_mapping(tmp_path: Path):
    eds = tmp_path / "metadata.eds"
    eds.write_text(
        """
[2000]
ParameterName=Sample
DataType=0x0006
AccessType=rw
LowLimit=1
HighLimit=100
PDOMapping=1
""".strip(),
        encoding="utf-8",
    )

    dictionary = CANopenDictionaryParser().load(eds)

    assert len(dictionary.entries) == 1
    entry = dictionary.entries[0]
    assert (entry.index, entry.subindex) == (0x2000, 0)
    assert entry.access_type == "rw"
    assert entry.low_limit == "1"
    assert entry.high_limit == "100"
    assert entry.pdo_mapping is True
    assert dictionary.pdo_mappings["TPDO1"] == [(0x2000, 0)]


def test_namespaced_xdd_extracts_object_and_communication_id(tmp_path: Path):
    xdd = tmp_path / "namespaced.xdd"
    xdd.write_text(
        """
<Root xmlns="urn:canopen:test">
  <Object index="0x2001" name="Status">
    <SubObject subIndex="0" name="Value" dataType="0x0005" accessType="ro" />
  </Object>
  <CommunicationObject name="TPDO1" cobId="0x185" />
</Root>
""".strip(),
        encoding="utf-8",
    )

    dictionary = CANopenDictionaryParser().load(xdd)

    assert len(dictionary.entries) == 1
    assert dictionary.entries[0].index == 0x2001
    assert dictionary.entries[0].subindex == 0
    assert dictionary.entries[0].access_type == "ro"
    assert dictionary.cob_ids["TPDO1"] == 0x185
