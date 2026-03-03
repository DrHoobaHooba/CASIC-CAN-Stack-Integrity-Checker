from __future__ import annotations

import argparse
from pathlib import Path

from casic.core.models import FuzzConfig
from casic.core.parser import CANopenDictionaryParser
from casic.protocols import CANopenFuzzer, J1939Fuzzer, RawCANFuzzer, UDSFuzzer


def _add_common_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("-i", dest="interface", required=True, help="CAN interface (e.g., can0)")
    parser.add_argument("-r", dest="rate_mode", type=int, default=1, help="rate mode (1=max speed)")
    parser.add_argument("-s", dest="source_mode", default="rand", help="source mode: rand or CAN-ID")
    parser.add_argument("-d", dest="destination", default="rand", help="destination CAN-ID / address")
    parser.add_argument("-p", dest="packet_count", type=int, default=1000000, help="packet count")
    parser.add_argument("-m", dest="print_interval", type=int, default=5000, help="print interval")
    parser.add_argument("-F", dest="flag_f", type=int, default=0)
    parser.add_argument("-V", dest="flag_v", type=int, default=0)
    parser.add_argument("-I", dest="flag_i", type=int, default=0)
    parser.add_argument("--seed", dest="seed", type=int, default=None)
    parser.add_argument("--replay", dest="replay_file", type=Path, default=None)
    parser.add_argument("--save-replay", dest="save_replay_file", type=Path, default=None)


def _config_from_args(args: argparse.Namespace) -> FuzzConfig:
    return FuzzConfig(
        interface=args.interface,
        rate_mode=args.rate_mode,
        source_mode=args.source_mode,
        destination=args.destination,
        packet_count=args.packet_count,
        print_interval=args.print_interval,
        flag_f=args.flag_f,
        flag_v=args.flag_v,
        flag_i=args.flag_i,
        seed=args.seed,
        replay_file=args.replay_file,
        save_replay_file=args.save_replay_file,
        node_id=getattr(args, "node_id", None),
        sdo_rx_cobid=getattr(args, "sdo_rx_cobid", None),
        sdo_tx_cobid=getattr(args, "sdo_tx_cobid", None),
        tpdo1_cobid=getattr(args, "tpdo1_cobid", None),
        rpdo1_cobid=getattr(args, "rpdo1_cobid", None),
        uds_request_id=getattr(args, "uds_request_id", None),
        uds_response_id=getattr(args, "uds_response_id", None),
        j1939_priority=getattr(args, "j1939_priority", None),
        j1939_pgn=getattr(args, "j1939_pgn", None),
        j1939_sa=getattr(args, "j1939_sa", None),
        j1939_da=getattr(args, "j1939_da", None),
        mutation_mode=getattr(args, "mutation", None),
        mutation_chain=getattr(args, "mutation_chain", None),
        mutation_rate=getattr(args, "mutation_rate", 1.0),
        payload_min_len=getattr(args, "payload_min_len", None),
        payload_max_len=getattr(args, "payload_max_len", None),
        raw_extended_id_probability=getattr(args, "raw_extended_id_probability", 0.0),
        raw_fd_probability=getattr(args, "raw_fd_probability", 0.0),
        raw_error_injection_probability=getattr(args, "raw_error_injection_probability", 0.0),
        uds_malformed_pci_probability=getattr(args, "uds_malformed_pci_probability", 0.0),
        uds_invalid_sid_probability=getattr(args, "uds_invalid_sid_probability", 0.0),
        uds_max_payload_len=getattr(args, "uds_max_payload_len", 50),
        j1939_tp_probability=getattr(args, "j1939_tp_probability", 0.1),
        j1939_invalid_pgn_probability=getattr(args, "j1939_invalid_pgn_probability", 0.0),
        canopen_invalid_sdo_probability=getattr(args, "canopen_invalid_sdo_probability", 0.0),
        canopen_mode_bias=getattr(args, "canopen_mode_bias", None),
    )


def main_cansic(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="cansic")
    _add_common_arguments(parser)
    parser.add_argument("--can-fd", action="store_true", help="Generate 64-byte CAN-FD payloads")
    parser.add_argument(
        "--mutation",
        choices=["none", "bitflip", "nibbleflip", "byteflip", "boundary", "truncate", "expand", "swap", "arithmetic", "structured"],
        default="bitflip",
    )
    parser.add_argument("--mutation-chain", default=None, help="Comma-separated mutation chain")
    parser.add_argument("--mutation-rate", type=float, default=1.0, help="Per-mutation apply probability (0..1)")
    parser.add_argument("--payload-min", dest="payload_min_len", type=int, default=None)
    parser.add_argument("--payload-max", dest="payload_max_len", type=int, default=None)
    parser.add_argument("--extended-prob", dest="raw_extended_id_probability", type=float, default=0.0)
    parser.add_argument("--fd-prob", dest="raw_fd_probability", type=float, default=0.0)
    parser.add_argument("--error-frame-prob", dest="raw_error_injection_probability", type=float, default=0.0)
    args = parser.parse_args(argv)
    fuzzer = RawCANFuzzer(_config_from_args(args), can_fd=args.can_fd, mutation_mode=args.mutation)
    fuzzer.run()


def main_udsic(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="udsic")
    _add_common_arguments(parser)
    parser.add_argument("--req-id", dest="uds_request_id", type=lambda x: int(x, 0), help="UDS request CAN-ID")
    parser.add_argument("--resp-id", dest="uds_response_id", type=lambda x: int(x, 0), help="UDS expected response CAN-ID")
    parser.add_argument("--malformed-pci-prob", dest="uds_malformed_pci_probability", type=float, default=0.0)
    parser.add_argument("--invalid-sid-prob", dest="uds_invalid_sid_probability", type=float, default=0.0)
    parser.add_argument("--uds-max-payload", dest="uds_max_payload_len", type=int, default=50)
    args = parser.parse_args(argv)
    fuzzer = UDSFuzzer(_config_from_args(args))
    fuzzer.run()


def main_j1939sic(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="j1939sic")
    _add_common_arguments(parser)
    parser.add_argument("--priority", dest="j1939_priority", type=int, choices=range(0, 8), help="J1939 priority (0-7)")
    parser.add_argument("--pgn", dest="j1939_pgn", type=lambda x: int(x, 0), help="J1939 PGN")
    parser.add_argument("--sa", dest="j1939_sa", type=lambda x: int(x, 0), help="J1939 source address")
    parser.add_argument("--da", dest="j1939_da", type=lambda x: int(x, 0), help="J1939 destination address")
    parser.add_argument("--tp-prob", dest="j1939_tp_probability", type=float, default=0.1)
    parser.add_argument("--invalid-pgn-prob", dest="j1939_invalid_pgn_probability", type=float, default=0.0)
    args = parser.parse_args(argv)
    fuzzer = J1939Fuzzer(_config_from_args(args))
    fuzzer.run()


def main_cosic(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(prog="cosic")
    _add_common_arguments(parser)
    parser.add_argument("--eds", dest="eds_file", type=Path)
    parser.add_argument("--xdd", dest="xdd_file", type=Path)
    parser.add_argument("--xdc", dest="xdc_file", type=Path)
    parser.add_argument("--node-id", dest="node_id", type=lambda x: int(x, 0), help="CANopen node ID")
    parser.add_argument("--sdo-rx", dest="sdo_rx_cobid", type=lambda x: int(x, 0), help="Override SDO client->server COB-ID")
    parser.add_argument("--sdo-tx", dest="sdo_tx_cobid", type=lambda x: int(x, 0), help="Override SDO server->client COB-ID")
    parser.add_argument("--tpdo1", dest="tpdo1_cobid", type=lambda x: int(x, 0), help="Override TPDO1 COB-ID")
    parser.add_argument("--rpdo1", dest="rpdo1_cobid", type=lambda x: int(x, 0), help="Override RPDO1 COB-ID")
    parser.add_argument("--invalid-sdo-prob", dest="canopen_invalid_sdo_probability", type=float, default=0.0)
    parser.add_argument(
        "--mode-bias",
        dest="canopen_mode_bias",
        choices=["balanced", "sdo-heavy", "pdo-heavy", "control-heavy"],
        default=None,
        help="Bias CANopen frame family generation",
    )
    args = parser.parse_args(argv)

    dictionary_file = args.eds_file or args.xdd_file or args.xdc_file
    dictionary = None
    if dictionary_file:
        dictionary = CANopenDictionaryParser().load(dictionary_file)
        print(
            f"[cosic] loaded dictionary entries={len(dictionary.entries)} "
            f"cob_ids={len(dictionary.cob_ids)}"
        )

    fuzzer = CANopenFuzzer(_config_from_args(args), dictionary=dictionary)
    fuzzer.run()
