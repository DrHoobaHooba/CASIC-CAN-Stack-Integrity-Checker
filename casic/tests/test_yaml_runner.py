from pathlib import Path

import pytest

from casic.cli.config_runner import run_from_yaml
from casic.cli.yaml_config import parse_int


def test_parse_int_hex_and_decimal():
    assert parse_int("0x7E0") == 0x7E0
    assert parse_int("123") == 123
    assert parse_int(42) == 42


def test_yaml_runner_skips_disabled_and_runs_enabled(tmp_path: Path):
    cfg = tmp_path / "casic.yaml"
    cfg.write_text(
        """
global:
  interface: can0
  packet_count: 1
  print_interval: 1

protocols:
  cansic:
    enabled: true
    mutation: none
  udsic:
    enabled: false
  j1939sic:
    enabled: false
  cosic:
    enabled: false
""".strip(),
        encoding="utf-8",
    )

    run_from_yaml(cfg)


def test_yaml_runner_rejects_invalid_probability_value(tmp_path: Path):
    cfg = tmp_path / "invalid.yaml"
    cfg.write_text(
        """
global:
  interface: can0
  packet_count: 1

protocols:
  cansic:
    enabled: true
    raw_fd_probability: 1.2
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="raw_fd_probability"):
        run_from_yaml(cfg)
