# CASIC — CAN Stack Integrity Checker

CASIC is an ISIC-style integrity fuzzing toolkit for CAN-based protocols.

## Warning

- This project contains AI-assisted/generated code.
- Review, test, and validate behavior in your target environment before production use.
- Fuzzing can destabilize devices and networks; use only in authorized and controlled test setups.

## Protocol Tools

- `cansic`: Raw CAN fuzzing
- `udsic`: UDS over CAN fuzzing (ISO 14229)
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

Runtime and validation notes:

- `rate_mode=1` is high-speed behavior; `rate_mode=0` enables explicit timer-based pacing in the shared send loop.
- Probability-style options (for example `--fd-prob`, `--invalid-sid-prob`, `--mutation-rate`) are validated in range `[0.0, 1.0]`.
- Payload bounds are validated (`payload_min_len <= payload_max_len`, non-negative values).

Protocol-specific targeting flags:

- `cosic`: `--node-id`, `--sdo-rx`, `--sdo-tx`, `--tpdo1`, `--rpdo1`
- `udsic`: `--req-id`, `--resp-id`
- `j1939sic`: `--priority`, `--pgn`, `--sa`, `--da`

Advanced fuzzing flags:

- `cansic`: `--mutation`, `--mutation-chain`, `--mutation-rate`, `--payload-min`, `--payload-max`, `--extended-prob`, `--fd-prob`, `--error-frame-prob`
- `udsic`: `--malformed-pci-prob`, `--invalid-sid-prob`, `--uds-max-payload`
- `j1939sic`: `--tp-prob`, `--invalid-pgn-prob`
- `cosic`: `--invalid-sdo-prob`, `--mode-bias`

Targeting precedence:

- Explicit protocol overrides win (`--sdo-rx`, `--req-id`, `--da`, etc.)
- Then protocol-derived values (for CANopen `--node-id`, for J1939 `-d` as DA fallback)
- Then dictionary/default/random fuzz values

Notes:

- `cosic`: `-d` acts as SDO RX COB-ID fallback if provided (for example `-d 0x605`).
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
udsic -i can0 -r 1 -s rand -d 0x7E0 -p200000 -m5000 --invalid-sid-prob 0.1 --malformed-pci-prob 0.2 --uds-max-payload 128
j1939sic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --tp-prob 0.2 --invalid-pgn-prob 0.1
cosic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --node-id 0x61 --invalid-sdo-prob 0.15 --mode-bias sdo-heavy --eds ./casic/examples/node.eds
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

- Raw CAN random IDs, extended-ID probability, CAN-FD probability, and payload size ranges
- Mutation operators: bitflip, nibbleflip, byteflip, boundary, truncate, expand, swap, arithmetic, structured
- Mutation chaining and per-mutation application probability
- UDS invalid SID, malformed ISO-TP PCI, variable payload range, and multi-frame fuzzing
- J1939 PGN/priority/SA/DA fuzzing plus transport-protocol and invalid-PGN probabilities
- CANopen dictionary-aware SDO/PDO/NMT/EMCY/SYNC/TIME generation with SDO corruption probability and mode bias

## Replay Support

Capture sent sequences:

```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p5000 -m1000 --eds ./casic/examples/node.eds --save-replay ./replay_cosic.jsonl
```

Replay captured sequence:

```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p1 -m1000 --replay ./replay_cosic.jsonl
```

## Development Roadmap

This roadmap is based on what is already implemented in the current codebase and highlights the next engineering priorities.

### Current baseline (v0.1.x)

- Multi-protocol fuzzers available: Raw CAN (`cansic`), UDS (`udsic`), J1939 (`j1939sic`), CANopen (`cosic`)
- Unified YAML runner (`casic --config`) with per-protocol enable/disable behavior
- Replay capture and replay execution (`--save-replay`, `--replay`)
- CANopen EDS/XDD/XDC dictionary parsing with dictionary-aware generation
- Dry-send fallback when `python-can` backend is unavailable
- Runtime validation for probability ranges and payload bounds with explicit error messages
- `rate_mode=0` timer-based pacing in the engine loop (`rate_mode=1` unchanged for high-speed)
- Legacy compatibility flags (`-F/-V/-I`) removed to keep CASIC CLI protocol-specific and explicit

### Next milestones (near term)

1. Runtime controls and validation
- Completed in current baseline; focus is now on profiling/tuning pacing policies and documenting operational guidance.

2. Protocol depth improvements
- UDS: extend negative-response and service-sequence awareness (session/security timing scenarios)
- J1939: improve transport-protocol realism for multi-packet message sequencing
- CANopen: increase dictionary constraint usage (access rights, limits, PDO mapping semantics)

3. Observability and diagnostics
- Add optional structured run summaries (JSON) with per-protocol counters
- Expand replay metadata (run id, seed, profile info) for better reproducibility
- Add a configurable response-correlation report for request/response fuzz sessions

### Mid-term milestones

1. Stability and quality
- Expand test coverage around protocol edge cases and replay compatibility
- Add CI matrix for Windows/Linux with and without optional CAN backend
- Introduce regression tests for example configs and CLI aliases

2. Configuration experience
- Add YAML schema validation and clearer config-time diagnostics
- Add reusable preset profiles for aggressive, balanced, and protocol-focused campaigns
- Add a dry-run config validation mode to verify setup before transmitting frames

### Longer-term goals

1. Safety and control-plane features
- Add optional guardrails (send budget, stop conditions, allow/deny ID ranges)
- Add campaign checkpointing and resumable fuzz runs

2. Integration and reporting
- Export machine-readable artifacts for CI/security pipelines
- Add protocol-specific post-run analysis helpers for triage and defect clustering

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
