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

### Development roadmap (v0.0.7+)

**v0.0.7** — Configuration experience and usability
- YAML schema validation with clear, actionable error messages
- Preset profiles (discovery-focused, conservative, aggressive)
- Dry-run validation mode (parse and verify config without sending frames)
- Enhanced diagnostics for troubleshooting config issues

**v0.0.8** — Safety guardrails and control-plane
- Send budget limits and stop conditions (max frames, time limits, error thresholds)
- Allow/deny ID ranges to prevent sensitive traffic
- Campaign checkpointing and resumable runs
- Safe defaults with clear warnings for destructive operations

**v0.0.9+** — Stability infrastructure and reporting
- CI/CD matrix (Windows/Linux, with/without optional CAN backend)
- Regression tests and integration tests for multi-protocol workflows
- Advanced analysis helpers for triage, defect clustering, and post-run correlation

### How contributors can align work

- Prioritize changes that improve determinism (`--seed` + replay fidelity)
- Include tests for every new CLI/config option
- Keep protocol behavior isolated per fuzzer while preserving the shared engine interface

## Notes

- If `python-can` is not installed or the interface is unavailable, CASIC runs in dry-send mode.
- Error frame injection depends on adapter/OS support and is left as a backend capability.
- Runtime artifacts such as `replay/`, `.pytest_cache/`, and `__pycache__/` are generated locally and excluded via `.gitignore`.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
