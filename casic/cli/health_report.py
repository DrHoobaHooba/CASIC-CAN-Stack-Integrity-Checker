from __future__ import annotations

import argparse
import csv
import json
import math
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


def _finite_number(value: Any, field: str, *, optional: bool = False) -> float | None:
    if optional and (value is None or value == ""):
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a number") from exc
    if not math.isfinite(number):
        raise ValueError(f"{field} must be finite")
    return number


def _percentile(values: list[float], percentile: int) -> float | None:
    if not values:
        return None
    values = sorted(values)
    index = max(0, min(len(values) - 1, round((percentile / 100) * (len(values) - 1))))
    return round(values[index], 3)


def _triage_signals(run: dict[str, Any]) -> list[dict[str, Any]]:
    signals = []
    summary = run.get("summary", {})
    if summary.get("sent", 0) > 0 and summary.get("received", 0) == 0:
        signals.append(
            {
                "kind": "no_responses_observed",
                "source": "summary",
                "observation": "The run counted no accepted application data frames.",
                "meaning": "Check response routing, filters, interface capture, target state, and whether this protocol is expected to respond.",
            }
        )
    if summary.get("errors", 0) > 0:
        signals.append(
            {
                "kind": "run_errors_recorded",
                "source": "summary",
                "count": summary["errors"],
                "observation": "The run recorded parse/receive errors.",
                "meaning": "Inspect tool logs and adapter diagnostics; this count is not a device-fault classification.",
            }
        )
    if summary.get("transport_errors", 0) > 0:
        signals.append({
            "kind": "transport_errors_recorded", "source": "summary",
            "count": summary["transport_errors"],
            "observation": "The adapter recorded open/send/receive/close failures.",
            "meaning": "Sent counts are attempts, not confirmed wire delivery. Inspect the response capture and tool logs.",
        })
    if summary.get("can_error_frames", 0) > 0:
        signals.append({
            "kind": "can_error_frames_observed", "source": "summary",
            "count": summary["can_error_frames"],
            "observation": "CAN error frames were observed separately from application responses.",
            "meaning": "Inspect adapter/bus diagnostics; CAN error frames are not ECU application replies or proof of a crash.",
        })
    correlation = run.get("correlation", {})
    if correlation.get("unsupported_reason"):
        signals.append(
            {
                "kind": "correlation_unavailable",
                "source": "correlation",
                "observation": correlation["unsupported_reason"],
                "meaning": "Request/response indicators are unavailable for this protocol.",
            }
        )
    elif correlation.get("request_count", 0) and correlation.get("unmatched_count", 0):
        signals.append(
            {
                "kind": "unmatched_requests_observed",
                "source": "correlation",
                "count": correlation["unmatched_count"],
                "observation": "Some recorded requests did not match a response within the configured correlation window.",
                "meaning": "Review the trace, filter, timeout window, and expected protocol behavior; unmatched does not prove a target failure.",
            }
        )
    return signals


def _load_summary(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{path}: could not read file: {exc}") from exc

    runs = payload.get("runs") if isinstance(payload, dict) else None
    if not isinstance(runs, list):
        raise ValueError(f"{path}: expected a JSON object with a 'runs' list")

    normalized = []
    for index, run in enumerate(runs):
        label = f"{path}: runs[{index}]"
        if not isinstance(run, dict):
            raise ValueError(f"{label} must be an object")
        for field in ("protocol", "run_id", "sent", "received", "errors", "duration_ms"):
            if field not in run:
                raise ValueError(f"{label} is missing {field!r}")

        sent = _finite_number(run["sent"], f"{label}.sent")
        received = _finite_number(run["received"], f"{label}.received")
        errors = _finite_number(run["errors"], f"{label}.errors")
        transport_errors = _finite_number(run.get("transport_errors", 0), f"{label}.transport_errors")
        if transport_errors < 0 or not transport_errors.is_integer():
            raise ValueError(f"{label}: transport_errors must be a non-negative whole-number count")
        duration_ms = _finite_number(run["duration_ms"], f"{label}.duration_ms")
        receive_counts = {}
        for field in ("observed_frames", "ordinary_received", "can_error_frames", "remote_frames"):
            if field in run:
                count = _finite_number(run[field], f"{label}.{field}")
                if count < 0 or not count.is_integer():
                    raise ValueError(f"{label}: {field} must be a non-negative whole-number count")
                receive_counts[field] = int(count)
        if any(value < 0 for value in (sent, received, errors, duration_ms)):
            raise ValueError(f"{label}: counts and duration must be non-negative")
        if not sent.is_integer() or not received.is_integer() or not errors.is_integer():
            raise ValueError(f"{label}: sent, received, and errors must be whole-number counts")

        normalized.append(
            {
                "protocol": str(run["protocol"]),
                "run_id": str(run["run_id"]),
                "seed": run.get("seed"),
                "profile_name": run.get("profile_name"),
                "sent": int(sent),
                "received": int(received),
                "errors": int(errors),
                "transport_errors": int(transport_errors),
                **receive_counts,
                "duration_ms": round(duration_ms, 3),
                "received_to_sent_percent": round(received / sent * 100, 3) if sent else None,
                "errors_per_1000_sent": round(errors / sent * 1000, 3) if sent else None,
            }
        )
    return normalized


def _load_correlations(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"matched": 0, "unmatched": 0, "latencies_ms": [], "unsupported_reason": None}
    )
    required_columns = {"protocol", "run_id", "match_status", "latency_ms", "summary_metric", "summary_value"}
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or not required_columns.issubset(reader.fieldnames):
                raise ValueError(
                    f"{path}: correlation CSV must contain columns "
                    f"{', '.join(sorted(required_columns))}"
                )
            for line_number, row in enumerate(reader, start=2):
                protocol = (row.get("protocol") or "").strip()
                run_id = (row.get("run_id") or "").strip()
                if not protocol or not run_id:
                    raise ValueError(f"{path}:{line_number}: protocol and run_id are required")
                group = groups[(protocol, run_id)]
                status = (row.get("match_status") or "").strip()
                if status == "matched":
                    group["matched"] += 1
                    latency = _finite_number(
                        row.get("latency_ms"),
                        f"{path}:{line_number}.latency_ms",
                        optional=True,
                    )
                    if latency is None or latency < 0:
                        raise ValueError(f"{path}:{line_number}: matched row needs non-negative latency_ms")
                    group["latencies_ms"].append(latency)
                elif status == "unmatched":
                    group["unmatched"] += 1
                elif status == "unsupported":
                    group["unsupported_reason"] = row.get("summary_value") or "Correlation unsupported"
                elif status:
                    raise ValueError(f"{path}:{line_number}: unrecognized match_status {status!r}")
    except OSError as exc:
        raise ValueError(f"{path}: could not read file: {exc}") from exc
    except csv.Error as exc:
        raise ValueError(f"{path}: invalid CSV: {exc}") from exc
    return groups


def _load_baseline(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid baseline JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{path}: could not read baseline: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or not isinstance(payload.get("runs"), list):
        raise ValueError(f"{path}: baseline must be a CASIC health report with schema_version 1 and runs")
    return payload


def _compare_to_baseline(runs: list[dict[str, Any]], baseline: dict[str, Any]):
    baseline_runs = baseline["runs"]
    for run in runs:
        current_summary = run.get("summary", {})
        profile = current_summary.get("profile_name")
        candidates = []
        for item in baseline_runs:
            if not isinstance(item, dict) or item.get("protocol") != run["protocol"]:
                continue
            baseline_summary = item.get("summary")
            if isinstance(baseline_summary, dict) and baseline_summary.get("profile_name") == profile:
                candidates.append(item)
        if len(candidates) != 1:
            run["baseline_comparison"] = {
                "status": "not_comparable",
                "reason": "no unique baseline run matched protocol and profile_name",
            }
            continue

        prior = candidates[0]
        deltas: dict[str, Any] = {}
        prior_summary = prior.get("summary", {})
        for field in ("received_to_sent_percent", "errors_per_1000_sent", "duration_ms"):
            current_value = current_summary.get(field)
            baseline_value = prior_summary.get(field)
            if isinstance(current_value, (int, float)) and isinstance(baseline_value, (int, float)):
                deltas[f"summary_{field}"] = round(current_value - baseline_value, 3)

        current_corr = run.get("correlation", {})
        baseline_corr = prior.get("correlation", {})
        for field in ("unmatched_percent",):
            current_value = current_corr.get(field)
            baseline_value = baseline_corr.get(field)
            if isinstance(current_value, (int, float)) and isinstance(baseline_value, (int, float)):
                deltas[f"correlation_{field}"] = round(current_value - baseline_value, 3)
        current_percentiles = current_corr.get("latency_percentiles_ms", {})
        baseline_percentiles = baseline_corr.get("latency_percentiles_ms", {})
        if not isinstance(current_percentiles, dict):
            current_percentiles = {}
        if not isinstance(baseline_percentiles, dict):
            baseline_percentiles = {}
        for percentile, current_value in current_percentiles.items():
            baseline_value = baseline_percentiles.get(percentile)
            if isinstance(current_value, (int, float)) and isinstance(baseline_value, (int, float)):
                deltas[f"latency_{percentile}_ms"] = round(current_value - baseline_value, 3)

        run["baseline_comparison"] = {
            "status": "compared",
            "baseline_run_id": prior.get("run_id"),
            "deltas_current_minus_baseline": deltas,
            "review_signals": [
                {
                    "kind": "baseline_metric_changed",
                    "metric": metric,
                    "direction": "increased" if delta > 0 else "decreased" if delta < 0 else "unchanged",
                    "delta": delta,
                    "meaning": "Descriptive change only; review test comparability and corroborating evidence.",
                }
                for metric, delta in deltas.items()
                if delta != 0
            ],
            "interpretation": "Differences are descriptive and have no pass/fail threshold.",
        }


def build_health_report(
    summary_paths: list[Path],
    correlation_paths: list[Path],
    baseline_path: Path | None = None,
) -> dict[str, Any]:
    if not summary_paths and not correlation_paths:
        raise ValueError("provide at least one --summary or --correlation input")

    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for path in summary_paths:
        for summary in _load_summary(path):
            key = (summary["protocol"], summary["run_id"])
            if key in runs:
                raise ValueError(f"duplicate run {key[0]}/{key[1]} across summary inputs")
            runs[key] = {"protocol": summary["protocol"], "run_id": summary["run_id"], "summary": summary}

    correlations: dict[tuple[str, str], dict[str, Any]] = {}
    for path in correlation_paths:
        for key, details in _load_correlations(path).items():
            if key in correlations:
                prior = correlations[key]
                prior["matched"] += details["matched"]
                prior["unmatched"] += details["unmatched"]
                prior["latencies_ms"].extend(details["latencies_ms"])
                prior["unsupported_reason"] = prior["unsupported_reason"] or details["unsupported_reason"]
            else:
                correlations[key] = details

    for key, details in correlations.items():
        matched = details["matched"]
        unmatched = details["unmatched"]
        observed = matched + unmatched
        latencies = details["latencies_ms"]
        correlation = {
            "request_count": observed,
            "matched_count": matched,
            "unmatched_count": unmatched,
            "unmatched_percent": round(unmatched / observed * 100, 3) if observed else None,
            "latency_percentiles_ms": {
                f"p{percentile}": _percentile(latencies, percentile)
                for percentile in (50, 90, 95, 99)
            },
            "unsupported_reason": details["unsupported_reason"],
        }
        runs.setdefault(key, {"protocol": key[0], "run_id": key[1]})["correlation"] = correlation

    result = {
        "schema_version": 1,
        "generated_at": time.time(),
        "assessment": "not_determined",
        "runs": sorted(runs.values(), key=lambda item: (item["protocol"], item["run_id"])),
        "interpretation": [
            "This report analyzes existing summary and correlation files only; it does not communicate with a CAN interface.",
            "Response gaps, receive counts, errors, and latency are observations, not proof of a crash, hang, or defect.",
            "Interpret measurements against a known-good baseline and confirm device state independently.",
            "Correlation detail is available only for protocols that produced matched/unmatched request rows.",
        ],
    }
    if baseline_path is not None:
        baseline = _load_baseline(baseline_path)
        _compare_to_baseline(result["runs"], baseline)
        result["baseline_source"] = str(baseline_path)
        result["interpretation"].append(
            "Baseline deltas are descriptive; they are not automatic failure diagnoses."
        )
    for run in result["runs"]:
        run["triage_signals"] = _triage_signals(run)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casic-health-report",
        description="Build an offline report from existing CASIC summary and correlation files.",
    )
    parser.add_argument("--summary", action="append", type=Path, default=[], help="Run summary JSON (repeatable)")
    parser.add_argument(
        "--correlation",
        action="append",
        type=Path,
        default=[],
        help="Correlation CSV (repeatable)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Existing casic-health-report JSON to compare against (offline, descriptive only)",
    )
    parser.add_argument("--output", type=Path, required=True, help="Output JSON report path")
    args = parser.parse_args(argv)

    try:
        report = build_health_report(args.summary, args.correlation, args.baseline)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Offline health report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
