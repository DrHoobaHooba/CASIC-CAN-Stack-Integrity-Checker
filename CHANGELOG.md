# Changelog

All notable changes to CASIC (CAN Stack Integrity Checker) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.6] — 2026-03-26

### Added

- **UDS ISO-TP edge-case controls**: added controls for single-frame and first-frame length mismatch, consecutive-frame sequence anomalies, and recovery probes (`uds_single_frame_length_mismatch_probability`, `uds_first_frame_length_mismatch_probability`, `uds_consecutive_frame_sequence_anomaly_probability`, `uds_recovery_probe_probability`)
- **J1939 TP deep fault controls**: added incomplete DT truncation, CM/DT ordering faults, and packet-count mismatch controls (`j1939_tp_incomplete_dt_probability`, `j1939_tp_cm_dt_order_fault_probability`, `j1939_tp_packet_count_mismatch_probability`)
- **CANopen stateful depth controls**: added NMT state-awareness and segmented download controls (`canopen_nmt_state_aware_probability`, `canopen_segmented_sdo_probability`) plus parser-backed array/subindex bounds-awareness (`canopen_array_bounds_aware_probability`)
- **CANopen dictionary metadata extension**: parser now captures subindex-0 array-size hints into dictionary metadata for bounds-aware generation
- **Expanded v0.0.6 test coverage**: added protocol behavior and config-validation tests for new UDS/J1939/CANopen depth features

### Changed

- Updated baseline and indepth YAML profiles to include v0.0.6 controls with practical and aggressive values
- Updated CLI/YAML and README flag surfaces to expose all v0.0.6 protocol-depth controls consistently

### Fixed

- **CANopen runtime parsing tolerance**: gracefully handles non-numeric data type strings (for example `UNKNOWN`) in optional integer parsing paths

### Notes

- Full test suite passes (`58 passed`)

## [0.0.5] — 2026-03-24

### Added

- **UDS adaptive sequencing controls**: new adaptive follow-up logic and NRC backoff behavior via `uds_adaptive_sequence_probability` and `uds_nrc_backoff_probability`
- **J1939 TP variant injection**: new TP DT sequence anomaly variants (`gap`, `duplicate`, `reorder`) and timing fault metadata support
- **CANopen abort-aware adaptation**: optional SDO abort-code-aware object blacklisting with configurable blacklist window
- **CLI and YAML knobs for deep variants**:
	- UDS: `--adaptive-sequence-prob`, `--nrc-backoff-prob`
	- J1939: `--tp-sequence-anomaly-prob`, `--tp-timing-fault-prob`
	- CANopen: `--abort-aware-prob`, `--abort-blacklist-window`
- **Expanded test coverage**: added focused tests for adaptive UDS behavior, J1939 TP anomaly/timing metadata, CANopen abort-aware blacklist adaptation, and new CLI/YAML validation paths

### Changed

- Updated example configs (`casic.yaml`, `casic-indepth.yaml`) with practical and aggressive defaults for new variant controls
- Updated README advanced flag and feature documentation to include newly added deep-variant controls

### Notes

- Full test suite passes (`45 passed`)

## [0.0.4] — 2026-03-23

### Added

- **Deterministic run IDs**: Run identifiers derived from protocol + canonicalized config hash for reproducible campaigns
- **Run summary JSON generation**: Structured output with per-protocol statistics (sent, received, errors, burst frames, duration)
- **Replay metadata enrichment**: JSONL records now include optional `run_id`, `seed`, and `profile_name` fields (backward compatible)
- **Request/response correlation reporting**: CSV output with latency percentiles and match rate metrics for UDS and J1939 protocols
- **CLI observability flags**: `--enable-summary`, `--summary-json`, `--enable-correlation`, `--correlation-csv`, `--correlation-window-seconds`, `--profile-name`
- **YAML observability configuration**: Global and per-protocol keys (`summary_enabled`, `summary_file`, `correlation_enabled`, `correlation_report_file`, `correlation_window_seconds`, `profile_name`)
- **Comprehensive test coverage**: 38 tests covering observability features, deterministic behavior, replay compatibility, and protocol correlation logic

### Fixed

- **YAML multi-protocol orchestration**: Aggregate summary JSON now guaranteed to write at run completion (added exception handling to prevent early exit)
- **Frame serialization**: Recursive handling of burst frames in replay metadata

### Changed

- Enhanced error reporting in `config_runner.py` with try-except blocks around protocol runs and summary writes
- Updated README with observability documentation and examples

### Notes

- Observability features are fully backward compatible; legacy JSONL replay records without metadata fields remain readable
- All 38 tests pass; no regressions detected

## [0.0.3] — 2026-03-01

### Added

- Multi-protocol fuzzing framework (Raw CAN, UDS, J1939, CANopen)
- Unified YAML runner with per-protocol enable/disable
- Replay capture and replay execution
- CANopen EDS/XDD/XDC dictionary parsing
- UDS sequence-aware and negative-response-aware generation
- J1939 transport-protocol CM/DT burst sequencing
- Runtime validation and error messages

## [0.0.2]

- Initial reference implementation
- Basic CLI and protocol fuzzers

## [0.0.1]

- Project foundation
