# Changelog

All notable changes to CASIC (CAN Stack Integrity Checker) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
