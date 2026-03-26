from pathlib import Path
import json

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


def test_udsic_rejects_out_of_range_adaptive_sequence_probability():
    with pytest.raises(ValueError, match="uds_adaptive_sequence_probability"):
        main_udsic(["-i", "can0", "-p", "1", "--adaptive-sequence-prob", "-0.1"])


def test_j1939_rejects_out_of_range_tp_sequence_anomaly_probability():
    with pytest.raises(ValueError, match="j1939_tp_sequence_anomaly_probability"):
        main_j1939sic(["-i", "can0", "-p", "1", "--tp-sequence-anomaly-prob", "2.0"])


def test_cosic_rejects_invalid_abort_blacklist_window():
    with pytest.raises(ValueError, match="canopen_abort_blacklist_window"):
        main_cosic(["-i", "can0", "-p", "1", "--abort-blacklist-window", "0"])


def test_udsic_rejects_out_of_range_cf_sequence_anomaly_probability():
    with pytest.raises(ValueError, match="uds_consecutive_frame_sequence_anomaly_probability"):
        main_udsic(["-i", "can0", "-p", "1", "--cf-sequence-anomaly-prob", "1.2"])


def test_j1939_rejects_out_of_range_tp_order_fault_probability():
    with pytest.raises(ValueError, match="j1939_tp_cm_dt_order_fault_probability"):
        main_j1939sic(["-i", "can0", "-p", "1", "--tp-order-fault-prob", "-0.1"])


def test_cosic_rejects_out_of_range_segmented_sdo_probability():
    with pytest.raises(ValueError, match="canopen_segmented_sdo_probability"):
        main_cosic(["-i", "can0", "-p", "1", "--segmented-sdo-prob", "1.1"])


def test_cli_default_observability_outputs_are_disabled(tmp_path: Path):
    summary_file = tmp_path / "summary.json"
    correlation_file = tmp_path / "corr.csv"

    main_cansic(["-i", "can0", "-p", "1", "-m", "0"])

    assert not summary_file.exists()
    assert not correlation_file.exists()


def test_udsic_cli_generates_summary_and_correlation_when_enabled(tmp_path: Path):
    summary_file = tmp_path / "uds_summary.json"
    correlation_file = tmp_path / "uds_corr.csv"

    main_udsic(
        [
            "-i",
            "can0",
            "-p",
            "1",
            "-m",
            "0",
            "--seed",
            "11",
            "--enable-summary",
            "--summary-json",
            str(summary_file),
            "--enable-correlation",
            "--correlation-csv",
            str(correlation_file),
        ]
    )

    summary = json.loads(summary_file.read_text(encoding="utf-8"))
    assert summary["run_count"] == 1
    assert summary["runs"][0]["protocol"] == "uds"
    assert len(summary["runs"][0]["run_id"]) == 16
    assert correlation_file.exists()
