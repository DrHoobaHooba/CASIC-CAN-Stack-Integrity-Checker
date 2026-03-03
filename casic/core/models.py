from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CANFrame:
    can_id: int
    data: bytes
    is_extended_id: bool = False
    is_fd: bool = False
    timestamp: float | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FuzzConfig:
    interface: str
    rate_mode: int
    source_mode: str
    destination: str
    packet_count: int
    print_interval: int
    flag_f: int
    flag_v: int
    flag_i: int
    seed: int | None = None
    replay_file: Path | None = None
    save_replay_file: Path | None = None
    node_id: int | None = None
    sdo_rx_cobid: int | None = None
    sdo_tx_cobid: int | None = None
    tpdo1_cobid: int | None = None
    rpdo1_cobid: int | None = None
    uds_request_id: int | None = None
    uds_response_id: int | None = None
    j1939_priority: int | None = None
    j1939_pgn: int | None = None
    j1939_sa: int | None = None
    j1939_da: int | None = None
    mutation_mode: str | None = None
    mutation_chain: str | None = None
    mutation_rate: float = 1.0
    payload_min_len: int | None = None
    payload_max_len: int | None = None
    raw_extended_id_probability: float = 0.0
    raw_fd_probability: float = 0.0
    raw_error_injection_probability: float = 0.0
    uds_malformed_pci_probability: float = 0.0
    uds_invalid_sid_probability: float = 0.0
    uds_max_payload_len: int = 50
    j1939_tp_probability: float = 0.1
    j1939_invalid_pgn_probability: float = 0.0
    canopen_invalid_sdo_probability: float = 0.0
    canopen_mode_bias: str | None = None


@dataclass(slots=True)
class FuzzStats:
    sent: int = 0
    received: int = 0
    parse_errors: int = 0


@dataclass(slots=True)
class DictionaryEntry:
    index: int
    subindex: int
    name: str
    data_type: str
    access_type: str
    default_value: str | None = None
    low_limit: str | None = None
    high_limit: str | None = None
    pdo_mapping: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CANopenDictionary:
    entries: list[DictionaryEntry] = field(default_factory=list)
    cob_ids: dict[str, int] = field(default_factory=dict)
    pdo_mappings: dict[str, list[tuple[int, int]]] = field(default_factory=dict)


@dataclass(slots=True)
class ReplayRecord:
    protocol: str
    frame: CANFrame
    note: str = ""
