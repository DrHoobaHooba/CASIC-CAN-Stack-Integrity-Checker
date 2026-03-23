from pathlib import Path
import json

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


def test_yaml_runner_rejects_invalid_uds_awareness_probability(tmp_path: Path):
    cfg = tmp_path / "invalid_uds_prob.yaml"
    cfg.write_text(
        """
global:
  interface: can0
  packet_count: 1

protocols:
  udsic:
    enabled: true
    uds_negative_response_awareness_probability: -0.1
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="uds_negative_response_awareness_probability"):
        run_from_yaml(cfg)


def test_yaml_runner_writes_aggregate_summary_when_enabled(tmp_path: Path):
    summary_file = tmp_path / "summary.json"
    cfg = tmp_path / "summary.yaml"
    cfg.write_text(
        f"""
global:
  interface: can0
  packet_count: 1
  print_interval: 0
  seed: 42
  summary_enabled: true
  summary_file: {summary_file.as_posix()}

protocols:
  cansic:
    enabled: true
    mutation: none
  udsic:
    enabled: true
  j1939sic:
    enabled: false
  cosic:
    enabled: false
""".strip(),
        encoding="utf-8",
    )

    run_from_yaml(cfg)

    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["run_count"] == 2
    assert {entry["protocol"] for entry in data["runs"]} == {"cansic", "uds"}
    for entry in data["runs"]:
        assert isinstance(entry["run_id"], str)
        assert len(entry["run_id"]) == 16


def test_yaml_runner_run_id_is_deterministic_for_same_config(tmp_path: Path):
    summary_a = tmp_path / "summary_a.json"
    summary_b = tmp_path / "summary_b.json"

    cfg_a = tmp_path / "a.yaml"
    cfg_a.write_text(
        f"""
global:
  interface: can0
  packet_count: 1
  print_interval: 0
  seed: 123
  summary_enabled: true
  summary_file: {summary_a.as_posix()}
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

    cfg_b = tmp_path / "b.yaml"
    cfg_b.write_text(
        f"""
global:
  interface: can0
  packet_count: 1
  print_interval: 0
  seed: 123
  summary_enabled: true
  summary_file: {summary_b.as_posix()}
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

    run_from_yaml(cfg_a)
    run_from_yaml(cfg_b)

    run_a = json.loads(summary_a.read_text(encoding="utf-8"))["runs"][0]["run_id"]
    run_b = json.loads(summary_b.read_text(encoding="utf-8"))["runs"][0]["run_id"]
    assert run_a == run_b
