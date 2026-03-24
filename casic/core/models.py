from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _validate_probability(name: str, value: float):
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in range [0.0, 1.0], got {value}")


def _validate_int_range(name: str, value: int | None, minimum: int, maximum: int):
    if value is None:
        return
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be in range [{minimum}, {maximum}], got {value}")


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
    seed: int | None = None
    replay_file: Path | None = None
    save_replay_file: Path | None = None
    summary_enabled: bool = False
    summary_file: Path | None = None
    correlation_enabled: bool = False
    correlation_report_file: Path | None = None
    correlation_window_seconds: float = 2.0
    profile_name: str | None = None
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
    uds_sequence_awareness_probability: float = 0.6
    uds_negative_response_awareness_probability: float = 0.6
    uds_adaptive_sequence_probability: float = 0.0
    uds_nrc_backoff_probability: float = 0.0
    uds_max_payload_len: int = 50
    j1939_tp_probability: float = 0.1
    j1939_invalid_pgn_probability: float = 0.0
    j1939_tp_sequence_anomaly_probability: float = 0.0
    j1939_tp_timing_fault_probability: float = 0.0
    canopen_invalid_sdo_probability: float = 0.0
    canopen_abort_aware_probability: float = 0.0
    canopen_abort_blacklist_window: int = 5
    canopen_mode_bias: str | None = None

    def __post_init__(self):
        if self.rate_mode not in (0, 1):
            raise ValueError(f"rate_mode must be 0 or 1, got {self.rate_mode}")

        if self.packet_count <= 0:
            raise ValueError(f"packet_count must be > 0, got {self.packet_count}")
        if self.print_interval < 0:
            raise ValueError(f"print_interval must be >= 0, got {self.print_interval}")

        if self.payload_min_len is not None and self.payload_min_len < 0:
            raise ValueError(f"payload_min_len must be >= 0, got {self.payload_min_len}")
        if self.payload_max_len is not None and self.payload_max_len < 0:
            raise ValueError(f"payload_max_len must be >= 0, got {self.payload_max_len}")
        if self.payload_min_len is not None and self.payload_max_len is not None:
            if self.payload_min_len > self.payload_max_len:
                raise ValueError(
                    "payload_min_len must be <= payload_max_len, "
                    f"got min={self.payload_min_len} max={self.payload_max_len}"
                )

        if self.uds_max_payload_len <= 0:
            raise ValueError(f"uds_max_payload_len must be > 0, got {self.uds_max_payload_len}")
        if self.correlation_window_seconds <= 0.0:
            raise ValueError(
                "correlation_window_seconds must be > 0.0, "
                f"got {self.correlation_window_seconds}"
            )
        if self.canopen_abort_blacklist_window <= 0:
            raise ValueError(
                "canopen_abort_blacklist_window must be > 0, "
                f"got {self.canopen_abort_blacklist_window}"
            )

        _validate_probability("mutation_rate", self.mutation_rate)
        _validate_probability("raw_extended_id_probability", self.raw_extended_id_probability)
        _validate_probability("raw_fd_probability", self.raw_fd_probability)
        _validate_probability("raw_error_injection_probability", self.raw_error_injection_probability)
        _validate_probability("uds_malformed_pci_probability", self.uds_malformed_pci_probability)
        _validate_probability("uds_invalid_sid_probability", self.uds_invalid_sid_probability)
        _validate_probability("uds_sequence_awareness_probability", self.uds_sequence_awareness_probability)
        _validate_probability(
            "uds_negative_response_awareness_probability",
            self.uds_negative_response_awareness_probability,
        )
        _validate_probability("uds_adaptive_sequence_probability", self.uds_adaptive_sequence_probability)
        _validate_probability("uds_nrc_backoff_probability", self.uds_nrc_backoff_probability)
        _validate_probability("j1939_tp_probability", self.j1939_tp_probability)
        _validate_probability("j1939_invalid_pgn_probability", self.j1939_invalid_pgn_probability)
        _validate_probability(
            "j1939_tp_sequence_anomaly_probability",
            self.j1939_tp_sequence_anomaly_probability,
        )
        _validate_probability("j1939_tp_timing_fault_probability", self.j1939_tp_timing_fault_probability)
        _validate_probability("canopen_invalid_sdo_probability", self.canopen_invalid_sdo_probability)
        _validate_probability("canopen_abort_aware_probability", self.canopen_abort_aware_probability)

        _validate_int_range("j1939_priority", self.j1939_priority, 0, 7)
        _validate_int_range("j1939_sa", self.j1939_sa, 0, 0xFF)
        _validate_int_range("j1939_da", self.j1939_da, 0, 0xFF)
        _validate_int_range("j1939_pgn", self.j1939_pgn, 0, 0x3FFFF)
        _validate_int_range("node_id", self.node_id, 1, 127)


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
    run_id: str | None = None
    seed: int | None = None
    profile_name: str | None = None


@dataclass(slots=True)
class ProtocolRunSummary:
    protocol: str
    run_id: str
    seed: int | None
    profile_name: str | None
    started_at: float
    ended_at: float
    duration_ms: float
    sent: int
    received: int
    errors: int
    burst_frames: int


@dataclass(slots=True)
class CorrelationRow:
    protocol: str
    run_id: str
    request_timestamp: float | None
    response_timestamp: float | None
    match_status: str
    latency_ms: float | None
    correlation_key: str
    request_context: dict[str, Any] = field(default_factory=dict)
    response_context: dict[str, Any] = field(default_factory=dict)
