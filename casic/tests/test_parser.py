from pathlib import Path

from casic.core.parser import CANopenDictionaryParser


def test_load_eds():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/node.eds"))
    assert len(dictionary.entries) >= 2
    assert dictionary.cob_ids["SDO_RX"] == 0x600


def test_load_xdd():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/drive.xdd"))
    assert len(dictionary.entries) >= 2
    assert "TPDO1" in dictionary.cob_ids


def test_load_xdc():
    parser = CANopenDictionaryParser()
    dictionary = parser.load(Path("casic/examples/module.xdc"))
    assert len(dictionary.entries) >= 2
    assert dictionary.cob_ids["RPDO1"] == 0x200
