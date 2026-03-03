from pathlib import Path

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
