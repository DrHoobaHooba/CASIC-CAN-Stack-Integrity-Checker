from pathlib import Path

from casic.cli.main import main_cansic, main_cosic, main_j1939sic, main_udsic


def test_cansic_cli_minimal():
    main_cansic(["-i", "can0", "-p", "1", "-m", "1", "-F0", "-V0", "-I0"])


def test_udsic_cli_minimal():
    main_udsic(["-i", "can0", "-p", "1", "-m", "1", "-F0", "-V0", "-I0"])


def test_j1939sic_cli_minimal():
    main_j1939sic(["-i", "can0", "-p", "1", "-m", "1", "-F0", "-V0", "-I0"])


def test_cosic_cli_with_eds():
    main_cosic(
        [
            "-i",
            "can0",
            "-p",
            "1",
            "-m",
            "1",
            "-F0",
            "-V0",
            "-I0",
            "--eds",
            str(Path("casic/examples/node.eds")),
        ]
    )
