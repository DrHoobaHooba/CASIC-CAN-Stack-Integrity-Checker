from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from casic.cli.yaml_config import load_yaml, parse_int, parse_path
from casic.cli.health_report import build_health_report
from casic.core.logging import PacketLogger
from casic.core.models import FuzzConfig
from casic.core.parser import CANopenDictionaryParser
from casic.core.parser import J1939DescriptionParser
from casic.core.parser.protocol_descriptions import load_uds_description
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer, UDSFuzzer


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    merged.update(override)
    return merged


def _build_common(protocol_name: str, global_cfg: dict[str, Any], protocol_cfg: dict[str, Any]) -> FuzzConfig:
    merged = _merge(global_cfg, protocol_cfg)
    return FuzzConfig(
        interface=str(merged.get("interface", "can0")),
        bitrate=merged.get("bitrate", 500000),
        uds_extended_id=merged.get("uds_extended_id", False),
        rate_mode=int(merged.get("rate_mode", 1)),
        source_mode=str(merged.get("source_mode", "rand")),
        destination=str(merged.get("destination", "rand")),
        packet_count=int(merged.get("packet_count", 1000000)),
        print_interval=int(merged.get("print_interval", 5000)),
        seed=parse_int(merged.get("seed")),
        replay_file=parse_path(merged.get("replay_file")),
        save_replay_file=parse_path(merged.get("save_replay_file")),
        save_responses=merged.get("save_responses", False),
        responses_file=parse_path(merged.get("responses_file")),
        response_drain_seconds=float(merged.get("response_drain_seconds", 0.1)),
        raw_feedback_probability=float(merged.get("raw_feedback_probability", 0.0)),
        canopen_feedback_probability=float(merged.get("canopen_feedback_probability", 0.0)),
        j1939_feedback_probability=float(merged.get("j1939_feedback_probability", 0.0)),
        summary_enabled=bool(merged.get("summary_enabled", False) or merged.get("summary_file")),
        summary_file=parse_path(merged.get("summary_file")),
        correlation_enabled=bool(
            merged.get("correlation_enabled", False) or merged.get("correlation_report_file")
        ),
        correlation_report_file=parse_path(merged.get("correlation_report_file")),
        correlation_window_seconds=float(merged.get("correlation_window_seconds", 2.0)),
        profile_name=str(merged.get("profile_name")) if merged.get("profile_name") is not None else None,
        node_id=parse_int(merged.get("node_id")),
        sdo_rx_cobid=parse_int(merged.get("sdo_rx_cobid")),
        sdo_tx_cobid=parse_int(merged.get("sdo_tx_cobid")),
        tpdo1_cobid=parse_int(merged.get("tpdo1_cobid")),
        rpdo1_cobid=parse_int(merged.get("rpdo1_cobid")),
        uds_request_id=parse_int(merged.get("uds_request_id")),
        uds_response_id=parse_int(merged.get("uds_response_id")),
        j1939_priority=parse_int(merged.get("j1939_priority")),
        j1939_pgn=parse_int(merged.get("j1939_pgn")),
        j1939_sa=parse_int(merged.get("j1939_sa")),
        j1939_da=parse_int(merged.get("j1939_da")),
        mutation_mode=str(merged.get("mutation")) if merged.get("mutation") is not None else None,
        mutation_chain=str(merged.get("mutation_chain")) if merged.get("mutation_chain") is not None else None,
        mutation_rate=float(merged.get("mutation_rate", 1.0)),
        payload_min_len=parse_int(merged.get("payload_min_len")),
        payload_max_len=parse_int(merged.get("payload_max_len")),
        raw_extended_id_probability=float(merged.get("raw_extended_id_probability", 0.0)),
        raw_fd_probability=float(merged.get("raw_fd_probability", 0.0)),
        raw_error_injection_probability=float(merged.get("raw_error_injection_probability", 0.0)),
        uds_malformed_pci_probability=float(merged.get("uds_malformed_pci_probability", 0.0)),
        uds_invalid_sid_probability=float(merged.get("uds_invalid_sid_probability", 0.0)),
        uds_sequence_awareness_probability=float(merged.get("uds_sequence_awareness_probability", 0.6)),
        uds_negative_response_awareness_probability=float(
            merged.get("uds_negative_response_awareness_probability", 0.6)
        ),
        uds_adaptive_sequence_probability=float(merged.get("uds_adaptive_sequence_probability", 0.0)),
        uds_nrc_backoff_probability=float(merged.get("uds_nrc_backoff_probability", 0.0)),
        uds_single_frame_length_mismatch_probability=float(
            merged.get("uds_single_frame_length_mismatch_probability", 0.0)
        ),
        uds_first_frame_length_mismatch_probability=float(
            merged.get("uds_first_frame_length_mismatch_probability", 0.0)
        ),
        uds_consecutive_frame_sequence_anomaly_probability=float(
            merged.get("uds_consecutive_frame_sequence_anomaly_probability", 0.0)
        ),
        uds_recovery_probe_probability=float(merged.get("uds_recovery_probe_probability", 0.0)),
        uds_max_payload_len=int(merged.get("uds_max_payload_len", 50)),
        j1939_tp_probability=float(merged.get("j1939_tp_probability", 0.1)),
        j1939_invalid_pgn_probability=float(merged.get("j1939_invalid_pgn_probability", 0.0)),
        j1939_tp_sequence_anomaly_probability=float(
            merged.get("j1939_tp_sequence_anomaly_probability", 0.0)
        ),
        j1939_tp_timing_fault_probability=float(merged.get("j1939_tp_timing_fault_probability", 0.0)),
        j1939_tp_incomplete_dt_probability=float(merged.get("j1939_tp_incomplete_dt_probability", 0.0)),
        j1939_tp_cm_dt_order_fault_probability=float(
            merged.get("j1939_tp_cm_dt_order_fault_probability", 0.0)
        ),
        j1939_tp_packet_count_mismatch_probability=float(
            merged.get("j1939_tp_packet_count_mismatch_probability", 0.0)
        ),
        canopen_invalid_sdo_probability=float(merged.get("canopen_invalid_sdo_probability", 0.0)),
        canopen_abort_aware_probability=float(merged.get("canopen_abort_aware_probability", 0.0)),
        canopen_abort_blacklist_window=int(merged.get("canopen_abort_blacklist_window", 5)),
        canopen_nmt_state_aware_probability=float(
            merged.get("canopen_nmt_state_aware_probability", 0.0)
        ),
        canopen_segmented_sdo_probability=float(merged.get("canopen_segmented_sdo_probability", 0.0)),
        canopen_array_bounds_aware_probability=float(
            merged.get("canopen_array_bounds_aware_probability", 0.0)
        ),
        canopen_mode_bias=str(merged.get("canopen_mode_bias")) if merged.get("canopen_mode_bias") is not None else None,
    )


def run_from_yaml(config_path: str | Path):
    data = load_yaml(config_path)
    global_cfg = data.get("global", {})
    protocols = data.get("protocols", {})
    if not isinstance(global_cfg, dict) or not isinstance(protocols, dict):
        raise ValueError("YAML must contain 'global' and 'protocols' mappings")

    order = ["cansic", "udsic", "j1939sic", "cosic"]
    configs = {
        name: _build_common(name, global_cfg, protocols[name])
        for name in order
        if isinstance(protocols.get(name), dict) and protocols[name].get("enabled", False)
    }
    capture_paths: set[Path] = set()
    for name, config in configs.items():
        if config.save_responses:
            protocol = {"udsic": "uds", "j1939sic": "j1939"}.get(name, name)
            path = (config.responses_file or Path(f"{protocol}_responses.jsonl")).resolve()
            if path in capture_paths:
                raise ValueError("Enabled protocols must use distinct responses_file paths")
            capture_paths.add(path)
    summaries = []
    summary_output_path: Path | None = None
    correlation_output_paths: list[Path] = []
    summary_reporting_configured = bool(global_cfg.get("summary_enabled", False) or global_cfg.get("summary_file"))
    summary_reporting_configured = summary_reporting_configured or any(
        isinstance(section, dict)
        and section.get("enabled", False)
        and bool(section.get("summary_enabled", False) or section.get("summary_file"))
        for section in protocols.values()
    )
    health_report_enabled = bool(global_cfg.get("health_report_enabled", summary_reporting_configured))
    health_report_output_path = parse_path(global_cfg.get("health_report_file"))

    def record_result(result, config: FuzzConfig):
        if result is not None:
            summaries.append(result)
            if config.correlation_enabled and config.correlation_report_file is not None:
                correlation_output_paths.append(config.correlation_report_file)

    for name in order:
        section = protocols.get(name, {})
        if not isinstance(section, dict):
            continue

        enabled = bool(section.get("enabled", False))
        if not enabled:
            print(f"[casic] skip {name} (enabled=false)")
            continue

        config = configs[name]
        uds_description = None
        j1939_description = None
        if name == "udsic":
            uds_description = load_uds_description(
                parse_path(section.get("odx")), parse_path(section.get("pdx")), section.get("odx_variant"),
            )
        elif name == "j1939sic" and section.get("dbc"):
            j1939_description = J1939DescriptionParser().load(Path(str(section["dbc"])))
            print(f"[j1939] loaded description messages={len(j1939_description.messages)} (metadata only)")
        if config.summary_enabled and summary_output_path is None:
            summary_output_path = config.summary_file or Path("casic_summary.json")
        if config.summary_enabled and config.summary_file is None:
            config.summary_file = summary_output_path
        if config.correlation_enabled and config.correlation_report_file is None:
            config.correlation_report_file = Path(f"{name}_correlation.csv")

        print(f"[casic] run {name} interface={config.interface} packets={config.packet_count}")

        try:
            if name == "cansic":
                can_fd = bool(section.get("can_fd", False))
                mutation = str(section.get("mutation", "bitflip"))
                result = RawCANFuzzer(config, can_fd=can_fd, mutation_mode=mutation).run(write_summary=False)
                record_result(result, config)
                continue

            if name == "udsic":
                result = UDSFuzzer(config, description=uds_description).run(write_summary=False)
                record_result(result, config)
                continue

            if name == "j1939sic":
                result = J1939Fuzzer(config, description=j1939_description).run(write_summary=False)
                record_result(result, config)
                continue

            if name == "cosic":
                dictionary_path = section.get("eds") or section.get("xdd") or section.get("xdc")
                dictionary = None
                if dictionary_path:
                    dictionary = CANopenDictionaryParser().load(Path(str(dictionary_path)))
                    print(
                        f"[casic] loaded CANopen dictionary entries={len(dictionary.entries)} "
                        f"cob_ids={len(dictionary.cob_ids)}"
                    )
                result = CANopenFuzzer(config, dictionary=dictionary).run(write_summary=False)
                record_result(result, config)
        except Exception as e:
            print(f"[casic] error in {name}: {type(e).__name__}: {e}")

    print(f"[casic] completed all protocols. writing aggregate summary to {summary_output_path} with {len(summaries)} runs")
    summary_written = False
    if summary_output_path is not None and summaries:
        try:
            PacketLogger.write_run_summary(Path(summary_output_path), summaries)
            print(f"[casic] aggregate summary written successfully to {summary_output_path}")
            summary_written = True
        except Exception as e:
            print(f"[casic] error writing summary: {type(e).__name__}: {e}")

    if health_report_enabled:
        summary_inputs = [summary_output_path] if summary_written and summary_output_path is not None else []
        if not summary_inputs and not correlation_output_paths:
            print("[casic] health report skipped: no current-run summary or correlation artifacts were produced")
            return
        if health_report_output_path is None:
            base_path = summary_output_path or Path("casic_summary.json")
            health_report_output_path = base_path.with_name(f"{base_path.stem}_health.json")

        report = build_health_report(summary_inputs, correlation_output_paths)
        health_report_output_path.parent.mkdir(parents=True, exist_ok=True)
        health_report_output_path.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[casic] offline health report written to {health_report_output_path}")


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="casic")
    parser.add_argument("--config", required=True, type=Path, help="YAML configuration file")
    args = parser.parse_args(argv)
    run_from_yaml(args.config)


if __name__ == "__main__":
    main()
