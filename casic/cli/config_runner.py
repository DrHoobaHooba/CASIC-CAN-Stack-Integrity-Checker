from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from casic.cli.yaml_config import load_yaml, parse_int, parse_path
from casic.core.models import FuzzConfig
from casic.core.parser import CANopenDictionaryParser
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer, UDSFuzzer


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    merged.update(override)
    return merged


def _build_common(protocol_name: str, global_cfg: dict[str, Any], protocol_cfg: dict[str, Any]) -> FuzzConfig:
    merged = _merge(global_cfg, protocol_cfg)
    return FuzzConfig(
        interface=str(merged.get("interface", "can0")),
        rate_mode=int(merged.get("rate_mode", 1)),
        source_mode=str(merged.get("source_mode", "rand")),
        destination=str(merged.get("destination", "rand")),
        packet_count=int(merged.get("packet_count", 1000000)),
        print_interval=int(merged.get("print_interval", 5000)),
        flag_f=int(merged.get("flag_f", 0)),
        flag_v=int(merged.get("flag_v", 0)),
        flag_i=int(merged.get("flag_i", 0)),
        seed=parse_int(merged.get("seed")),
        replay_file=parse_path(merged.get("replay_file")),
        save_replay_file=parse_path(merged.get("save_replay_file")),
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
        uds_max_payload_len=int(merged.get("uds_max_payload_len", 50)),
        j1939_tp_probability=float(merged.get("j1939_tp_probability", 0.1)),
        j1939_invalid_pgn_probability=float(merged.get("j1939_invalid_pgn_probability", 0.0)),
        canopen_invalid_sdo_probability=float(merged.get("canopen_invalid_sdo_probability", 0.0)),
        canopen_mode_bias=str(merged.get("canopen_mode_bias")) if merged.get("canopen_mode_bias") is not None else None,
    )


def run_from_yaml(config_path: str | Path):
    data = load_yaml(config_path)
    global_cfg = data.get("global", {})
    protocols = data.get("protocols", {})
    if not isinstance(global_cfg, dict) or not isinstance(protocols, dict):
        raise ValueError("YAML must contain 'global' and 'protocols' mappings")

    order = ["cansic", "udsic", "j1939sic", "cosic"]
    for name in order:
        section = protocols.get(name, {})
        if not isinstance(section, dict):
            continue

        enabled = bool(section.get("enabled", False))
        if not enabled:
            print(f"[casic] skip {name} (enabled=false)")
            continue

        config = _build_common(name, global_cfg, section)
        print(f"[casic] run {name} interface={config.interface} packets={config.packet_count}")

        if name == "cansic":
            can_fd = bool(section.get("can_fd", False))
            mutation = str(section.get("mutation", "bitflip"))
            RawCANFuzzer(config, can_fd=can_fd, mutation_mode=mutation).run()
            continue

        if name == "udsic":
            UDSFuzzer(config).run()
            continue

        if name == "j1939sic":
            J1939Fuzzer(config).run()
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
            CANopenFuzzer(config, dictionary=dictionary).run()


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="casic")
    parser.add_argument("--config", required=True, type=Path, help="YAML configuration file")
    args = parser.parse_args(argv)
    run_from_yaml(args.config)
