from pathlib import Path

import pytest

from casic.cli.main import main_cansic, main_cosic, main_j1939sic, main_udsic


def test_cansic_cli_minimal():
    main_cansic(["-i", "can0", "-p", "1", "-m", "1"])


def test_udsic_cli_minimal():
    main_udsic(["-i", "can0", "-p", "1", "-m", "1"])


def test_j1939sic_cli_minimal():
    main_j1939sic(["-i", "can0", "-p", "1", "-m", "1"])


def test_cosic_cli_with_eds():
    main_cosic(
        [
            "-i",
            "can0",
            "-p",
            "1",
            "-m",
            "1",
            "--eds",
            str(Path("casic/examples/node.eds")),
        ]
    )


def test_cansic_rejects_out_of_range_probability():
    with pytest.raises(ValueError, match="raw_fd_probability"):
        main_cansic(["-i", "can0", "-p", "1", "--fd-prob", "1.5"])


def test_cansic_rejects_invalid_payload_bounds():
    with pytest.raises(ValueError, match="payload_min_len must be <= payload_max_len"):
        main_cansic(["-i", "can0", "-p", "1", "--payload-min", "9", "--payload-max", "8"])


def test_udsic_rejects_out_of_range_sequence_awareness_probability():
    with pytest.raises(ValueError, match="uds_sequence_awareness_probability"):
        main_udsic(["-i", "can0", "-p", "1", "--sequence-awareness-prob", "1.5"])
