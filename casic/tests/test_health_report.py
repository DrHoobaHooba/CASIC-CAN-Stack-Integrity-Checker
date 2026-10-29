import csv
import json
from pathlib import Path

import pytest

from casic.cli.health_report import build_health_report, main


def _write_summary(path: Path, *, sent: int = 10, received: int = 3):
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "protocol": "uds",
                        "run_id": "run-1",
                        "seed": 12,
                        "profile_name": "test-profile",
                        "sent": sent,
                        "received": received,
                        "errors": 1,
                        "duration_ms": 200,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_correlation(path: Path):
    rows = [
        {
            "protocol": "uds",
            "run_id": "run-1",
            "match_status": "matched",
            "latency_ms": "10",
            "summary_metric": "",
            "summary_value": "",
        },
        {
            "protocol": "uds",
            "run_id": "run-1",
            "match_status": "matched",
            "latency_ms": "30",
            "summary_metric": "",
            "summary_value": "",
        },
        {
            "protocol": "uds",
            "run_id": "run-1",
            "match_status": "unmatched",
            "latency_ms": "",
            "summary_metric": "",
            "summary_value": "",
        },
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def test_offline_report_combines_summary_and_correlation(tmp_path: Path):
    summary = tmp_path / "summary.json"
    correlation = tmp_path / "correlation.csv"
    _write_summary(summary)
    _write_correlation(correlation)

    report = build_health_report([summary], [correlation])
    run = report["runs"][0]

    assert report["assessment"] == "not_determined"
    assert run["summary"]["received_to_sent_percent"] == 30.0
    assert run["correlation"]["request_count"] == 3
    assert run["correlation"]["unmatched_percent"] == pytest.approx(33.333)
    assert run["correlation"]["latency_percentiles_ms"]["p50"] == 10.0
    assert any("not proof" in note for note in report["interpretation"])


def test_offline_report_reports_zero_received_percentage(tmp_path: Path):
    summary = tmp_path / "summary.json"
    _write_summary(summary, received=0)

    report = build_health_report([summary], [])

    assert report["runs"][0]["summary"]["received_to_sent_percent"] == 0.0
    assert report["runs"][0]["triage_signals"][0]["kind"] == "no_responses_observed"


def test_offline_report_includes_unsupported_correlation_metadata(tmp_path: Path):
    correlation = tmp_path / "correlation.csv"
    fields = ["protocol", "run_id", "match_status", "latency_ms", "summary_metric", "summary_value"]
    with correlation.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "protocol": "cosic",
                "run_id": "run-2",
                "match_status": "unsupported",
                "summary_metric": "unsupported_reason",
                "summary_value": "No request-response correlation",
            }
        )

    report = build_health_report([], [correlation])

    assert report["runs"][0]["correlation"]["unsupported_reason"] == "No request-response correlation"


def test_offline_report_rejects_invalid_summary_counts(tmp_path: Path):
    summary = tmp_path / "summary.json"
    _write_summary(summary, sent=-1)

    with pytest.raises(ValueError, match="non-negative"):
        build_health_report([summary], [])


def test_health_report_cli_writes_json_without_device_access(tmp_path: Path):
    summary = tmp_path / "summary.json"
    output = tmp_path / "reports" / "health.json"
    _write_summary(summary)

    assert main(["--summary", str(summary), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["assessment"] == "not_determined"


def test_health_report_compares_current_metrics_to_baseline(tmp_path: Path):
    summary = tmp_path / "summary.json"
    baseline = tmp_path / "baseline.json"
    _write_summary(summary, sent=10, received=3)
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runs": [
                    {
                        "protocol": "uds",
                        "run_id": "baseline-run",
                        "summary": {
                            "profile_name": "test-profile",
                            "received_to_sent_percent": 20.0,
                            "errors_per_1000_sent": 100.0,
                            "duration_ms": 150.0,
                        },
                        "correlation": {
                            "unmatched_percent": 10.0,
                            "latency_percentiles_ms": {"p50": 8.0},
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_health_report([summary], [], baseline)
    comparison = report["runs"][0]["baseline_comparison"]

    assert comparison["status"] == "compared"
    assert comparison["baseline_run_id"] == "baseline-run"
    assert comparison["deltas_current_minus_baseline"]["summary_received_to_sent_percent"] == 10.0
    assert comparison["deltas_current_minus_baseline"]["summary_duration_ms"] == 50.0
    assert any(
        signal["metric"] == "summary_received_to_sent_percent"
        and signal["direction"] == "increased"
        for signal in comparison["review_signals"]
    )


def test_health_report_marks_ambiguous_baseline_not_comparable(tmp_path: Path):
    summary = tmp_path / "summary.json"
    baseline = tmp_path / "baseline.json"
    _write_summary(summary)
    baseline.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runs": [
                    {"protocol": "uds", "run_id": "base-a", "summary": {"profile_name": "test-profile"}},
                    {"protocol": "uds", "run_id": "base-b", "summary": {"profile_name": "test-profile"}},
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_health_report([summary], [], baseline)

    assert report["runs"][0]["baseline_comparison"]["status"] == "not_comparable"
