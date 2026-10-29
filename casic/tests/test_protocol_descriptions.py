import json
from pathlib import Path
import zipfile

import pytest

from casic.core.parser import J1939DescriptionParser, UDSDescriptionParser
from casic.core.parser.protocol_descriptions import load_uds_description


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.mark.parametrize("filename", ["synthetic.odx-d", "synthetic.pdx"])
def test_load_odx_and_pdx(filename):
    pytest.importorskip("odxtools")
    description = UDSDescriptionParser().load(EXAMPLES / "uds" / filename)
    assert description.variant == "SyntheticBenchVariant"
    assert description.services[0].service_id == 0x22
    assert description.services[0].constants["SyntheticIdentifier"] == 0x1234


def test_unknown_odx_variant_rejected():
    pytest.importorskip("odxtools")
    with pytest.raises(ValueError, match="unknown or ambiguous variant"):
        UDSDescriptionParser().load(EXAMPLES / "uds" / "synthetic.odx-d", variant="Absent")


def test_multiple_odx_variants_require_selection(tmp_path):
    pytest.importorskip("odxtools")
    original = (EXAMPLES / "uds" / "synthetic.odx-d").read_text(encoding="utf-8")
    alternate = """<ECU-VARIANT ID="DL.OTHER"><SHORT-NAME>Other</SHORT-NAME></ECU-VARIANT>"""
    path = tmp_path / "multiple.odx-d"
    path.write_text(original.replace("</ECU-VARIANTS>", alternate + "</ECU-VARIANTS>"), encoding="utf-8")
    with pytest.raises(ValueError, match="select odx_variant"):
        UDSDescriptionParser().load(path)
    assert UDSDescriptionParser().load(path, variant="SyntheticBenchVariant").services


def test_conflicting_description_paths_rejected():
    with pytest.raises(ValueError, match="only one"):
        load_uds_description(Path("a.odx"), Path("b.pdx"))
    with pytest.raises(ValueError, match="requires"):
        load_uds_description(None, None, "Variant")


def test_load_j1939_dbc():
    pytest.importorskip("cantools")
    description = J1939DescriptionParser().load(EXAMPLES / "j1939" / "synthetic.dbc")
    message = description.messages[0]
    assert message.pgn == 0xFEF3
    assert message.priority == 6
    assert message.source_address == 0x3A
    assert message.destination_address is None
    assert message.signals[0].spn == 4321
    assert message.signals[0].scale == 0.25
    assert message.signals[1].offset == -40


def test_j1939_pdu1_and_page_bits(tmp_path):
    pytest.importorskip("cantools")
    identifier = (4 << 26) | (1 << 24) | (0xEF << 16) | (0x56 << 8) | 0x42
    path = tmp_path / "pdu1.dbc"
    path.write_text(
        'VERSION ""\nNS_ :\nBS_:\nBU_: Node\n'
        f"BO_ {identifier | 0x80000000} Example: 8 Node\n"
        ' SG_ Value : 0|8@1+ (1,0) [0|255] "" Vector__XXX\n',
        encoding="utf-8",
    )
    message = J1939DescriptionParser().load(path).messages[0]
    assert message.pgn == 0x1EF00
    assert message.destination_address == 0x56
    assert message.source_address == 0x42


def test_invalid_formats_and_missing_files():
    with pytest.raises(ValueError, match="expected"):
        UDSDescriptionParser().load("wrong.txt")
    with pytest.raises(FileNotFoundError):
        J1939DescriptionParser().load("absent.dbc")


def test_invalid_odx_and_pdx_fail_explicitly(tmp_path):
    pytest.importorskip("odxtools")
    path = tmp_path / "broken.odx-d"
    path.write_text("<ODX>", encoding="utf-8")
    from xml.etree.ElementTree import ParseError
    with pytest.raises(ParseError):
        UDSDescriptionParser().load(path)
    pdx = tmp_path / "broken.pdx"
    pdx.write_bytes(b"not an archive")
    with pytest.raises(zipfile.BadZipFile):
        UDSDescriptionParser().load(pdx)


def test_description_cli_is_offline(capsys):
    pytest.importorskip("cantools")
    from casic.cli.describe import main
    assert main([str(EXAMPLES / "j1939" / "synthetic.dbc")]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["messages"][0]["signals"][0]["spn"] == 4321


def test_yaml_and_cli_pass_descriptions_without_opening_transport(tmp_path, monkeypatch):
    pytest.importorskip("cantools")
    pytest.importorskip("odxtools")
    from casic.cli import config_runner, main as cli
    received = []

    class FakeFuzzer:
        def __init__(self, config, description=None):
            received.append(description)

        def run(self, **kwargs):
            return None

    for module in (config_runner, cli):
        monkeypatch.setattr(module, "UDSFuzzer", FakeFuzzer)
        monkeypatch.setattr(module, "J1939Fuzzer", FakeFuzzer)
    odx = EXAMPLES / "uds" / "synthetic.odx-d"
    dbc = EXAMPLES / "j1939" / "synthetic.dbc"
    cli.main_udsic(["-i", "unused", "--odx", str(odx)])
    cli.main_j1939sic(["-i", "unused", "--dbc", str(dbc)])
    import yaml
    config = tmp_path / "descriptions.yaml"
    config.write_text(yaml.safe_dump({
        "protocols": {
            "udsic": {"enabled": True, "odx": str(odx)},
            "j1939sic": {"enabled": True, "dbc": str(dbc)},
        }
    }), encoding="utf-8")
    config_runner.run_from_yaml(config)
    assert [type(item).__name__ for item in received] == [
        "UDSDescription", "J1939Description", "UDSDescription", "J1939Description",
    ]
