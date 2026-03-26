# CASIC - CAN Stack Integrity Checker

CASIC is an ISIC-style integrity fuzzing toolkit for CAN-based protocols.

## Warning

- This project contains AI-assisted/generated code.
- Review, test, and validate behavior in your target environment before production use.
- Fuzzing can destabilize devices and networks; use only in authorized and controlled test setups.

## Protocol Tools

- `cansic`: Raw CAN fuzzing
- `udsic`: UDS over CAN fuzzing (ISO 14229/ISO-TP)
- `j1939sic`: SAE J1939 fuzzing
- `cosic`: CANopen fuzzing (CiA 301)

## Project Layout

```text
casic/
  core/
    generator/
    mutation/
    logging/
    parser/
    transport/
  protocols/
    raw_can/
    uds/
    j1939/
    canopen/
  cli/
  tests/
  examples/
```

## Installation

```bash
pip install -e .
```

Optional CAN backend:

```bash
pip install -e .[can]
```

For PCAN on Windows, install PEAK PCAN-Basic drivers and keep `python-can` installed.

## Quick Start (PCAN)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .[can]
$env:Path = "$(Resolve-Path .\.venv\Scripts);$env:Path"
casic --config .\casic\examples\casic.yaml
```

### Windows direct command setup (no manual venv activation)

From project root in PowerShell:

```powershell
$env:Path = "$(Resolve-Path .\.venv\Scripts);$env:Path"
```

Then run directly in that shell:

```powershell
casic -h
cansic -h
udsic -h
j1939sic -h
cosic -h
```

If you want to use the helper script and your machine blocks scripts by policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
. .\tools\enable-casic.ps1
```

To persist for new terminals:

```powershell
.\tools\enable-casic.ps1 -Persist
```

### Linux direct command setup (no manual venv activation)

From project root in Bash/Zsh:

```bash
export PATH="$(pwd)/.venv/bin:$PATH"
```

Then run directly in that shell:

```bash
casic -h
cansic -h
udsic -h
j1939sic -h
cosic -h
```

Using helper script (must be sourced to affect current shell):

```bash
source ./tools/enable-casic.sh
```

To persist for new terminals:

```bash
source ./tools/enable-casic.sh --persist
```

For Linux CAN adapters (SocketCAN), bring up the interface before running CASIC:

```bash
sudo ip link set can0 up type can bitrate 500000
```

## CLI Pattern (ISIC style)

In addition to per-protocol binaries, CASIC supports a unified YAML-driven runner:

```bash
casic --config ./casic/examples/casic.yaml
```

`enabled: false` means that protocol section is skipped and its options are ignored.

Common flags:

- `-i <interface>`
- `-r <rate mode>`
- `-s <source mode>`
- `-d <destination>`
- `-p <packet count>`
- `-m <print interval>`
- `--seed N`
- `--enable-summary`
- `--summary-json <path>`
- `--enable-correlation`
- `--correlation-csv <path>`
- `--correlation-window-seconds <seconds>`
- `--profile-name <name>`

Runtime and validation notes:

- `rate_mode=1` is high-speed behavior; `rate_mode=0` enables explicit timer-based pacing in the shared send loop.
- Probability-style options (for example `--fd-prob`, `--invalid-sid-prob`, `--mutation-rate`) are validated in range `[0.0, 1.0]`.
- Payload bounds are validated (`payload_min_len <= payload_max_len`, non-negative values).
- `--mutation-chain` overrides `--mutation` when both are provided.
- `--can-fd` forces CAN-FD frame generation (up to 64-byte payloads).

Protocol-specific targeting flags:

- `cosic`: `--node-id`, `--sdo-rx`, `--sdo-tx`, `--tpdo1`, `--rpdo1`
- `udsic`: `--req-id`, `--resp-id`
- `j1939sic`: `--priority`, `--pgn`, `--sa`, `--da`

Advanced fuzzing flags:

- `cansic`: `--mutation`, `--mutation-chain`, `--mutation-rate`, `--payload-min`, `--payload-max`, `--extended-prob`, `--fd-prob`, `--can-fd`, `--error-frame-prob`
- `udsic`: `--malformed-pci-prob`, `--invalid-sid-prob`, `--sequence-awareness-prob`, `--negative-response-awareness-prob`, `--adaptive-sequence-prob`, `--nrc-backoff-prob`, `--sf-length-mismatch-prob`, `--ff-length-mismatch-prob`, `--cf-sequence-anomaly-prob`, `--recovery-probe-prob`, `--uds-max-payload`
- `j1939sic`: `--tp-prob`, `--invalid-pgn-prob`, `--tp-sequence-anomaly-prob`, `--tp-timing-fault-prob`, `--tp-incomplete-dt-prob`, `--tp-order-fault-prob`, `--tp-packet-count-mismatch-prob`
- `cosic`: `--invalid-sdo-prob`, `--abort-aware-prob`, `--abort-blacklist-window`, `--nmt-state-aware-prob`, `--segmented-sdo-prob`, `--array-bounds-aware-prob`, `--mode-bias`

Observability and diagnostics flags:

- `--enable-summary` enables summary generation; `--summary-json` sets output path
- `--enable-correlation` enables request/response correlation report generation; `--correlation-csv` sets output path
- `--correlation-window-seconds` controls matching window (default: `2.0`)
- `--profile-name` tags replay metadata for reproducibility workflows

Targeting precedence:

- Explicit protocol overrides win (`--sdo-rx`, `--req-id`, `--da`, etc.)
- Then protocol-derived values (for CANopen `--node-id`, for J1939 `-d` as DA fallback)
- Then dictionary/default/random fuzz values

Notes:

- `cosic`: `-d` acts as SDO RX COB-ID fallback if provided (for example `-d 0x605`); if `--node-id` is omitted and `-d` is in `0x600..0x67F`, node_id is inferred from `-d`.
- `udsic`: `--resp-id` filters counted received responses to that CAN-ID.
- `j1939sic`: if `--da` is omitted and `-d` is set, low byte of `-d` is used as DA.

### Examples

```bash
cansic   -i can0 -r 1 -s rand -d rand       -p1000000 -m5000 --seed 42
udsic    -i can0 -r 1 -s rand -d 0x7E0      -p1000000 -m10000
j1939sic -i can0 -r 1 -s rand -d 0x18FF50E5 -p10000000 -m5000
cosic    -i can0 -r 1 -s rand -d 0x600      -p1000000 -m5000 --eds ./casic/examples/node.eds
```

### YAML configuration example

Use [casic/examples/casic.yaml](casic/examples/casic.yaml) to enable only selected protocols and keep the rest disabled.

```yaml
global:
  interface: pcan:PCAN_USBBUS1
  packet_count: 10000
  print_interval: 1000

protocols:
  cansic:
    enabled: true
    mutation: bitflip

  udsic:
    enabled: false
    uds_request_id: 0x7E0

  j1939sic:
    enabled: false

  cosic:
    enabled: true
    node_id: 0x05
    eds: ./casic/examples/node.eds
```

For an aggressive all-protocol profile with all fuzzing knobs enabled, use:

```bash
casic --config ./casic/examples/casic-indepth.yaml
```

`casic/examples/casic-indepth.yaml` enables all four protocol sections (`cansic`, `udsic`, `j1939sic`, `cosic`) and includes aggressive values for UDS ISO-TP mismatch/recovery controls, J1939 TP sequencing and ordering faults, and CANopen segmented-SDO/state-aware adaptation.

### Observability YAML keys

The following keys are optional in both `global` and per-protocol sections:

- `summary_enabled: true|false`
- `summary_file: ./artifacts/run-summary.json`
- `correlation_enabled: true|false`
- `correlation_report_file: ./artifacts/uds-correlation.csv`
- `correlation_window_seconds: 2.0`
- `profile_name: campaign-a`

Default behavior is unchanged unless these are explicitly enabled.

### Deterministic node/address targeting examples

```bash
cosic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --node-id 0x05 --eds ./casic/examples/node.eds
cosic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --sdo-rx 0x605 --tpdo1 0x185 --eds ./casic/examples/node.eds
udsic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --req-id 0x7E0 --resp-id 0x7E8
j1939sic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --priority 3 --pgn 0xFEF2 --sa 0x80 --da 0xFE
```

### Advanced mutation/fuzzing examples

```bash
cansic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --mutation-chain bitflip,boundary,swap --mutation-rate 0.7 --payload-min 2 --payload-max 8 --extended-prob 0.1
cansic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --mutation-chain bitflip,boundary,swap --mutation-rate 0.7 --payload-min 2 --payload-max 64 --can-fd --fd-prob 0.3
udsic -i can0 -r 1 -s rand -d 0x7E0 -p200000 -m5000 --invalid-sid-prob 0.1 --malformed-pci-prob 0.2 --sequence-awareness-prob 0.8 --cf-sequence-anomaly-prob 0.15 --recovery-probe-prob 0.2 --uds-max-payload 128
j1939sic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --tp-prob 0.2 --invalid-pgn-prob 0.1 --tp-incomplete-dt-prob 0.1 --tp-order-fault-prob 0.05
cosic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --node-id 0x61 --invalid-sdo-prob 0.15 --segmented-sdo-prob 0.2 --nmt-state-aware-prob 0.25 --mode-bias sdo-heavy --eds ./casic/examples/node.eds
```

### PCAN (Windows) examples

```bash
cansic -i pcan:PCAN_USBBUS1 -r 1 -s rand -d rand -p100000 -m5000
udsic  -i pcan:PCAN_USBBUS1 -r 1 -s rand -d 0x7E0 -p500000 -m10000
cosic  -i pcan:PCAN_USBBUS1 -r 1 -s rand -d 0x600 -p500000 -m5000 --eds ./casic/examples/node.eds
```

You can also pass `-i PCAN_USBBUS1` directly on Windows; CASIC auto-selects the `pcan` backend.

## CANopen File Support

`cosic` supports:

- `--eds <path>`
- `--xdd <path>`
- `--xdc <path>`

The parser extracts object dictionary entries, PDO mapping, SDO parameters, COB-IDs, and basic constraints.

## Fuzzing Features

- Raw CAN random IDs, extended-ID probability, explicit CAN-FD mode (`--can-fd`), CAN-FD probability (`--fd-prob`), and payload size ranges
- Mutation operators: bitflip, nibbleflip, byteflip, boundary, truncate, expand, swap, arithmetic, structured
- Mutation chaining and per-mutation application probability
- UDS invalid SID, malformed ISO-TP PCI, variable payload range, multi-frame fuzzing, sequence/NRC-aware service selection, adaptive follow-up/backoff behavior, ISO-TP length mismatches, consecutive-frame anomalies, and recovery probes
- J1939 PGN/priority/SA/DA fuzzing plus transport-protocol CM/DT burst sequencing, invalid-PGN probabilities, TP sequence anomaly injection, incomplete DT bursts, CM/DT ordering faults, packet-count mismatches, and timing fault metadata
- CANopen dictionary-aware SDO/PDO/NMT/EMCY/SYNC/TIME generation with access-rights and limit-aware SDO behavior, segmented download bursts, NMT state-aware transitions, parser-backed array/subindex bounds awareness, PDO mapping semantics, SDO corruption probability, abort-aware SDO adaptation, and mode bias

## Replay Support

Capture sent sequences:

```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p5000 -m1000 --eds ./casic/examples/node.eds --save-replay ./replay_cosic.jsonl
```

Replay captured sequence:

```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p1 -m1000 --replay ./replay_cosic.jsonl
```

Replay records are additive and backward compatible. New records include optional metadata fields:

- `run_id` deterministic identifier derived from protocol plus canonicalized config
- `seed` seed used for generation (or `null`)
- `profile_name` optional campaign/profile label

Older JSONL records without these fields remain readable.

## Observability Outputs

### Summary JSON

Summary JSON is written only when enabled.

- Single protocol CLI: one-run summary payload
- YAML multi-protocol runner: one aggregate file written at run completion

Required run fields include:

- `protocol`, `run_id`, `seed`, `profile_name`
- `started_at`, `ended_at`, `duration_ms`
- `sent`, `received`, `errors`, `burst_frames`

### Correlation CSV

Correlation CSV is written only when enabled.

- UDS key: service/request context
- J1939 key: PGN plus addressing context

Each detail row includes:

- `request_timestamp`, `response_timestamp`, `match_status`, `latency_ms`
- `correlation_key`, `request_context`, `response_context`

The report appends summary metrics:

- `match_rate_percent`
- `unmatched_requests`
- `latency_p50_ms`, `latency_p90_ms`, `latency_p95_ms`, `latency_p99_ms`

For unsupported protocols (`cansic`, `cosic`), a metadata-only correlation artifact is emitted when correlation is enabled.

## Development Roadmap

This roadmap is based on what is already implemented in the current codebase and highlights the next engineering priorities.

### Current baseline (v0.0.6)

- Multi-protocol fuzzers available: Raw CAN (`cansic`), UDS (`udsic`), J1939 (`j1939sic`), CANopen (`cosic`)
- Unified YAML runner (`casic --config`) with per-protocol enable/disable behavior
- Replay capture and replay execution (`--save-replay`, `--replay`)
- CANopen EDS/XDD/XDC dictionary parsing with dictionary-aware generation
- UDS sequence-aware and negative-response-aware request generation controls
- UDS adaptive sequencing and NRC backoff controls
- UDS ISO-TP single-frame and first-frame length mismatch variants
- UDS consecutive-frame sequence anomaly and recovery-probe variants
- J1939 transport-protocol CM/DT multi-packet burst sequencing
- J1939 TP sequence anomaly and timing-fault variant generation
- J1939 TP incomplete DT, CM/DT ordering fault, and packet-count mismatch variants
- CANopen dictionary constraint usage in generation (access rights, limits, PDO mapping semantics)
- CANopen abort-aware response adaptation with temporary object blacklist window
- CANopen segmented SDO download generation and NMT state-aware control transitions
- CANopen parser-backed array/subindex bounds-aware selection behavior
- Dry-send fallback when `python-can` backend is unavailable
- Runtime validation for probability ranges and payload bounds with explicit error messages
- `rate_mode=0` timer-based pacing in the engine loop (`rate_mode=1` unchanged for high-speed)
- Legacy compatibility flags (`-F/-V/-I`) removed to keep CASIC CLI protocol-specific and explicit
- **Deterministic run IDs** based on protocol + canonicalized config hash
- **Run summary JSON** generation with per-protocol counters and durations
- **Replay metadata enrichment** with run_id, seed, profile_name (backward compatible)
- **Request/response correlation CSV** reporting with latency percentiles (UDS and J1939)
- **Fixed** aggregate summary generation in YAML multi-protocol orchestration

## Development Roadmap

This roadmap is based on identified gaps in the current codebase and prioritizes fixes by impact.

### Current Baseline (v0.0.6)

- Multi-protocol fuzzers: Raw CAN (`cansic`), UDS (`udsic`), J1939 (`j1939sic`), CANopen (`cosic`)
- Unified YAML runner (`casic --config`) with per-protocol enable/disable
- Replay capture/execution with metadata enrichment (run_id, seed, profile_name)
- CANopen EDS/XDD/XDC dictionary parsing with constraint-aware generation
- UDS sequence/NRC-aware request generation and adaptive controls
- J1939 TP multi-packet burst sequencing with anomaly injection
- CANopen abort-aware adaptation and state-aware NMT transitions
- Request/response correlation CSV reporting (UDS and J1939)
- Run summary JSON with per-protocol counters

### v0.0.7 — Critical Safety & Protocol Correctness

**Goal**: Fix critical gaps preventing silent data corruption and ensure replay integrity.

#### 1. Protocol Mismatch Detection on Replay ⚠️
**Problem**: Loading UDS replay into J1939 fuzzer succeeds without validation; can silently corrupt campaign data

**Work**:
- Add protocol field validation in `packet_logger.load_replay()`
- Raise explicit error if loaded replay protocol ≠ current fuzzer protocol
- Provide clear guidance to user on protocol mismatch

**Test**: `test_replay_protocol_mismatch()` in `test_mutation_and_replay.py`  
**Complexity**: Low

#### 2. Transport Error Visibility 🔴
**Problem**: SocketCAN silently swallows exceptions beyond "queue full"; real failures (cable loss, power failure, interface down) go unnoticed

**Work**:
- Replace silent exception handler in `socketcan.py:send()`
- Log all send failures with descriptive messages
- Track failures in `FuzzStats.errors` counter
- Document error visibility in CLI output

**Test**: `test_transport_failures()` in `test_runtime_controls.py`  
**Complexity**: Low

#### 3. CAN-ID Range Validation
**Problem**: Generator produces invalid CAN identifiers beyond legal ranges

**Work**:
- Validate standard IDs ≤ 0x7FF, extended IDs ≤ 0x1FFFFFFF in `random_generator.can_id()`
- Fix J1939 address range to include 0xFF (currently stops at 0xFE)
- Add validation at frame generation time, not just parse time

**Test**: `test_can_id_boundary_validation()` in `test_yaml_runner.py`  
**Complexity**: Low

#### 4. Replay Schema Versioning
**Problem**: No version field; future breaking changes to replay format will silently break old replays

**Work**:
- Add optional `replay_schema_version: "1.0"` to `ReplayRecord` model
- Update `packet_logger.save_replay()` / `load_replay()` for version handling
- Prepare backward compatibility path for v2.0+ schema evolution

**Test**: `test_replay_schema_versioning()` in `test_mutation_and_replay.py`  
**Complexity**: Low

**Expected impact**: v0.0.7 closes all 4 critical gaps with minimal code changes and strong test coverage.

---

### v0.0.8 — Stateful Protocol Handling & Correlation Depth

**Goal**: Implement proper state restoration for UDS/J1939/CANopen and deepen request/response correlation visibility.

#### 1. J1939 Stateful Response Handling
**Problem**: J1939 TP frames are generated independently; no BAM connection state tracking or abort sequence recognition

**Work**:
- Implement `on_response()` in `j1939/fuzzer.py` to track:
  - Inbound RTS (Request to Send) and outbound CM (Connection Management)
  - BAM connection state machine (idle → awaiting DT → complete)
  - Abort sequence recognition
- Apply timing fault metadata during burst send (currently unused)
- Maintain burst sequence context across response window

**Test**:
- `test_j1939_bam_state_tracking()` in `test_j1939_tp.py`
- `test_j1939_timing_fault_application()`
- `test_j1939_abort_sequences()`

**Complexity**: Medium

#### 2. UDS State Restoration on Replay
**Problem**: Replaying UDS campaigns loses session state and security unlock status; exact replay sequence differs from original

**Work**:
- Capture UDS state in `ReplayRecord`: `session_state`, `security_level`, `last_nrc`
- Update `uds/fuzzer.py:on_response()` to record state changes
- Restore state in `engine.py:replay()` before replaying frames
- Thread state through stateful frame generation

**Test**:
- `test_uds_replay_session_restore()` in `test_uds_awareness.py`
- `test_uds_replay_security_state()`

**Complexity**: Medium

#### 3. CANopen Stateful Response Handling
**Problem**: Limited response handling; missing NMT transitions, segmented SDO toggle bit tracking, heartbeat monitoring

**Work**:
- Enhance `canopen/fuzzer.py:on_response()` to:
  - Validate NMT state transitions (e.g., guard PDO/EMCY based on state)
  - Track segmented SDO toggle bit across multi-segment downloads
  - Implement heartbeat timeout detection
  - Log state violations for correlation

**Test**:
- `test_canopen_nmt_transitions()` in `test_canopen_constraints.py`
- `test_canopen_segmented_sdo_toggle()`
- `test_canopen_heartbeat_timeout()`

**Complexity**: Medium

#### 4. Enhanced Correlation Reports
**Problem**: CANopen and J1939 correlation reports lack depth

**Work**:
- **CANopen**: Add SDO request/response matching by index/subindex, NMT state transitions
- **J1939**: Add sequence number alignment across TP bursts, BAM connection context
- Extend correlation window logic to support protocol-specific matching

**Test**: `test_correlation_csv_completeness()` in `test_cli.py`  
**Complexity**: Medium

**Acceptance criteria**: All state changes captured, replay produces identical request/response patterns as original run, correlation reports include protocol-specific context fields.

---

### v0.0.9 — Code Quality, Maintenance & Completeness

**Goal**: Reduce technical debt, improve refactorability, and close remaining testing gaps.

#### 1. UDS Generation Logic Refactoring
**Problem**: `uds/fuzzer.py:generate_frame()` has 7+ levels of nested probability if/elif; unmaintainable

**Work**:
- Extract probability selection into strategy pattern or decision table
- Clarify probability hierarchy and precedence rules
- Make it easy to add new probability-based generation modes

**Test**: All existing UDS tests pass; add `test_uds_probability_precedence()`  
**Complexity**: Medium

#### 2. Metadata Namespace Formalization
**Problem**: Frame metadata using ad-hoc dict keys with no collision protection

**Work**:
- Define reserved `frame.meta` keys in `models.py` docstring
- Namespace by protocol: `meta["uds.*"]`, `meta["j1939.*"]`, `meta["canopen.*"]`
- Add optional collision detection in frame generation

**Test**: `test_metadata_namespace_reserved_keys()` in `test_mutation_and_replay.py`  
**Complexity**: Low

#### 3. Parser Error Handling & Validation
**Problem**: CANopen dictionary parser silently defaults missing attributes

**Work**:
- Log warnings for missing XML attributes (not silent defaults)
- Validate data type enums against known types
- Detect malformed PDO mappings and flag with warnings
- Improve error messages for common issues

**Test**: `test_parser_error_recovery()` in `test_parser.py`  
**Complexity**: Low

#### 4. Burst Frame Integrity Validation
**Problem**: No detection if SocketCAN reorders frames under load

**Work**:
- Add optional reorder detection in `engine.py:_send_burst()`
- Log warning if burst timestamps are out-of-order
- Provide diagnostic context for reordering issues

**Test**: `test_burst_frame_reordering_detection()` in `test_runtime_controls.py`  
**Complexity**: Low

#### 5. Completeness of Testing
**Problem**: Missing test coverage for edge cases and error paths

**Work**:
- Add tests for all gaps identified above
- Ensure all protocols have response handling tests
- Add integration tests for multi-protocol YAML runs
- Test CAN interface unavailable / dry-send path

**Test**: 8+ new test files/cases in existing tests  
**Complexity**: Low (per test, high volume)

**Acceptance criteria**: Test coverage ≥ 85% of main fuzzer paths; all error scenarios tested; integration tests for multi-protocol workflows pass consistently.

---

### v0.1.0+ — Advanced Features & Operational Excellence

**Goal**: Enable checkpoint/resume, advanced analysis, and extended protocol support.

#### 1. Replay State Machine Persistence *(depends on v0.0.8)*
- Serialize UDS/J1939/CANopen state machines into replay metadata
- Enable true deterministic replay with full state fidelity

#### 2. Campaign Checkpointing & Resumable Runs
- Add checkpoint format (replay offset + state snapshot)
- Implement CLI `--resume-from-checkpoint` flag
- Support long-running campaigns with interruption recovery

#### 3. Advanced Analysis Helpers
- Defect clustering for correlation data
- Triage helpers for common device error patterns
- Post-run analysis dashboard (JSON or HTML export)

#### 4. Extended CANopen Features
- LSS (Layer Setting Service) state machine support
- Time synchronization (SYNC) aware pacing
- Heartbeat producer/consumer validation

---

## Contribution & Priority Notes

For contributors:
- **v0.0.7 priority**: Focus on safety fixes; low complexity, high impact
- **v0.0.8 priority**: Deepen stateful protocol support; medium complexity, enables replay trustworthiness
- **v0.0.9 priority**: Refactor and test coverage; improves long-term maintainability
- When adding features, include tests and ensure replay determinism is preserved
- Keep protocol behavior isolated per fuzzer while respecting shared engine interface

**Known limitations** (tracked for future fixes):
- UDS/J1939 state loss on replay (v0.0.8)
- Silent transport failures (v0.0.7)
- CANopen limited stateful handling (v0.0.8)
- Nested UDS generation logic (v0.0.9)

## Notes

- If `python-can` is not installed or the interface is unavailable, CASIC runs in dry-send mode.
- Error frame injection depends on adapter/OS support and is left as a backend capability.
- Runtime artifacts such as `replay/`, `.pytest_cache/`, and `__pycache__/` are generated locally and excluded via `.gitignore`.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
