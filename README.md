# CASIC - CAN Stack Integrity Checker

CASIC is an ISIC-style integrity fuzzing toolkit for CAN-based protocols.

## Warning

- This project contains AI-assisted/generated code.
- Review, test, and validate behavior in your target environment before production use.
- Fuzzing can destabilize devices and networks; use only in authorized and controlled test setups.

## Fuzzing Basics

**This is a protocol mutation fuzzer.** It generates malformed/unexpected frames to find stack violations. Here's what to expect:

- **Objective**: Trigger crashes, hangs, resource exhaustion, or state violations in a firmware stack
- **Start small**: Run 10k–100k packets first to check for immediate crashes
- **Scale up**: Once stable, increase to millions of packets with high mutation rates
- **Monitor**: Watch logs and device response times—timeouts or errors suggest vulnerabilities
- **Interpret correlation**: High mismatch rate → likely protocol state issues; timeout → deadlock/hang risk
- **Success**: A crash or unrecoverable state in the target firmware indicates a finding

**Targeting tips**:
- For CANopen: Start with `cosic` and dictionary-aware SDO fuzzing
- For UDS: Focus on `udsic` with sequence-awareness enabled to stress multi-frame handling
- For J1939: Use `j1939sic` with TP timing faults to test transport robustness
- For raw CAN: Use `cansic` as a baseline to find basic acceptance filter issues

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
- `--bitrate <bit/s>` (default 500000; applied to PCAN, while SocketCAN configuration remains external)
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
- `udsic`: `--req-id`, `--resp-id`, `--extended-id`
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

YAML accepts `bitrate` globally or per protocol (integer, 10000..1000000 bit/s).
UDS automatically uses extended CAN frames for IDs above `0x7FF`; set
`uds_extended_id: true` (CLI `--extended-id`) to force extended format for smaller
numeric identifiers too. Both first/single frames and consecutive-frame bursts use
that format, and response-ID filtering checks the format as well as the numeric ID.
This is CAN identifier support, not a full flow-controlled ISO-TP client, ECU state
restoration, or automatic application of ODX communication parameters.

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
cosic    -i can0 -r 1 -s rand -d 0x600      -p1000000 -m5000 --eds ./casic/examples/canopen/node.eds
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
    eds: ./casic/examples/canopen/node.eds
```

For broad classic-CAN stress with mixed random/feedback generation, use:

```bash
casic --config ./casic/examples/casic-indepth.yaml
```

`casic/examples/casic-indepth.yaml` is a broad **classic-CAN** stress example,
not a full-conformance test or a device-health verdict. It enables all four
protocol sections with one million primary generations each, response/failure
capture, and mixed random/feedback-guided generation. Replace the synthetic
IDs, bitrate, and CANopen dictionary, and select only protocols supported on the
connected port before use.

The profile mixes standard/extended raw IDs and 0..8-byte classic payloads.
FD and raw `expand` mutation are disabled because the current PCAN path does not
configure FD and expansion happens after payload sizing. UDS uses up to 24 random
extra bytes to exercise both single-frame and short multi-frame paths. For
long-burst/CF-sequence-wrap testing, run a separate campaign with
`uds_max_payload_len: 512`; that setting makes single-frame candidates rare.
J1939 varies PGNs/priorities and mixes single messages with BAM/RTS-like bursts.
CANopen mixes existing frame families and expedited/segmented SDO generation
with observed-heartbeat and abort feedback.

Bursts mean the total frame count exceeds the configured primary count.
Sent/accepted-received frames are still retained in memory, replay serialization
adds memory overhead, and correlation matching can be expensive at million-scale
counts. Plan RAM/disk capacity and archive outputs between runs/seeds.
The profile cannot add missing flow-controlled transport handshakes, applied TP
timing faults (the timing knob currently records metadata only), full CANopen
array/PDO mapping coverage from the tiny synthetic EDS, or active before/after
health confirmation. Offline tests verify generated-path coverage, not live
delivery, device robustness, or standards conformance.

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
cosic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --node-id 0x05 --eds ./casic/examples/canopen/node.eds
cosic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --sdo-rx 0x605 --tpdo1 0x185 --eds ./casic/examples/canopen/node.eds
udsic    -i can0 -r 1 -s rand -d rand -p200000 -m5000 --req-id 0x7E0 --resp-id 0x7E8
j1939sic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --priority 3 --pgn 0xFEF2 --sa 0x80 --da 0xFE
```

### Advanced mutation/fuzzing examples

```bash
cansic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --mutation-chain bitflip,boundary,swap --mutation-rate 0.7 --payload-min 2 --payload-max 8 --extended-prob 0.1
cansic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --mutation-chain bitflip,boundary,swap --mutation-rate 0.7 --payload-min 2 --payload-max 64 --can-fd --fd-prob 0.3
udsic -i can0 -r 1 -s rand -d 0x7E0 -p200000 -m5000 --invalid-sid-prob 0.1 --malformed-pci-prob 0.2 --sequence-awareness-prob 0.8 --cf-sequence-anomaly-prob 0.15 --recovery-probe-prob 0.2 --uds-max-payload 128
j1939sic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --tp-prob 0.2 --invalid-pgn-prob 0.1 --tp-incomplete-dt-prob 0.1 --tp-order-fault-prob 0.05
cosic -i can0 -r 1 -s rand -d rand -p200000 -m5000 --node-id 0x61 --invalid-sdo-prob 0.15 --segmented-sdo-prob 0.2 --nmt-state-aware-prob 0.25 --mode-bias sdo-heavy --eds ./casic/examples/canopen/node.eds
```

### PCAN (Windows) examples

```bash
cansic -i pcan:PCAN_USBBUS1 -r 1 -s rand -d rand -p100000 -m5000
udsic  -i pcan:PCAN_USBBUS1 -r 1 -s rand -d 0x7E0 -p500000 -m10000
cosic  -i pcan:PCAN_USBBUS1 -r 1 -s rand -d 0x600 -p500000 -m5000 --eds ./casic/examples/canopen/node.eds
```

You can also pass `-i PCAN_USBBUS1` directly on Windows; CASIC auto-selects the `pcan` backend.

## CANopen File Support

The CANopen samples now live in `casic/examples/canopen/` (previously directly in `examples/`).

`cosic` supports:

- `--eds <path>`
- `--xdd <path>`
- `--xdc <path>`

The parser extracts object dictionary entries, PDO mapping, SDO parameters, COB-IDs, and basic constraints.

**Finding dictionary files**:
- Check your device manufacturer's website under "technical documentation" or "device files"
- Common sources: PEAK System Technik, Vector Informatik, device manuals
- Validate format: EDS (INI-style plain text), XDD/XDC (XML files)

**Common parsing issues**:
- Missing data type definitions → parser logs warnings but continues
- Malformed PDO mappings → check dictionary file for syntax errors
- Limited data types → not all vendor extensions are supported

## UDS and J1939 description files

Install the optional, maintained format parsers:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[descriptions]"
```

- **UDS:** `.odx`, `.odx-d`, and `.pdx` via `odxtools`. The loader summarizes resolved services and directly coded request constants. If multiple ECU variants exist, specify `--odx-variant` / `odx_variant`; no arbitrary variant is chosen.
- **J1939:** `.dbc` via `cantools`. The loader summarizes extended message IDs, PGNs, priority/source/destination addresses and signal metadata (SPN where supplied, bit layout, scale/offset, limits and units). DBC is widely used for J1939 signal definitions but is not a complete diagnostic or network-management specification. No proprietary SAE database is included.

These are **metadata loaders**, not new dictionary-driven generators: attaching a description does not automatically apply its addresses, timing, security algorithms, signal encodings or requests to generated traffic. Existing generator behavior is unchanged.

Inspect files **offline**, without opening any CAN interface:

```powershell
.\.venv\Scripts\python.exe -m casic.cli.describe .\casic\examples\uds\synthetic.odx-d
.\.venv\Scripts\python.exe -m casic.cli.describe .\casic\examples\uds\synthetic.pdx
.\.venv\Scripts\python.exe -m casic.cli.describe .\casic\examples\j1939\synthetic.dbc
```

The installed equivalent is `casic-describe <file> [--variant <short-name>]`.
Protocol CLI options are `udsic --odx <file> [--odx-variant <name>]`, `udsic --pdx <file>`, and `j1939sic --dbc <file>`. Unlike `casic-describe`, those protocol commands still run their existing fuzzers.

YAML options in the corresponding protocol block:

```yaml
protocols:
  udsic:
    enabled: false
    odx: ./casic/examples/uds/synthetic.odx-d  # or pdx, never both
    odx_variant: SyntheticBenchVariant
  j1939sic:
    enabled: false
    dbc: ./casic/examples/j1939/synthetic.dbc
```

Disabled sections are not loaded. Relative paths follow the existing convention: they are relative to the process working directory, not the YAML location. Invalid files and ambiguous variants fail explicitly.

Sample layout (synthetic demonstration data, not a real device configuration):

```text
casic/examples/
  casic.yaml
  casic-indepth.yaml
  canopen/
    node.eds
    drive.xdd
    module.xdc
  uds/
    synthetic.odx-d
    synthetic.pdx
  j1939/
    synthetic.dbc
```

The PDX sample is a ZIP containing the adjacent synthetic ODX-D file. New sample identifiers and values are invented, not taken from the connected device. The ODX sample deliberately contains no transport addresses or reset service.

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
cosic -i can0 -r 1 -s rand -d 0x600 -p5000 -m1000 --eds ./casic/examples/canopen/node.eds --save-replay ./replay_cosic.jsonl
```

Replay captured sequence:

```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p1 -m1000 --replay ./replay_cosic.jsonl
```

**Reproducibility**: Use `--seed <N>` with the same config to reproduce identical fuzz sequences. To replay a specific campaign:

```bash
casic --config ./casic/examples/casic.yaml --seed 12345
# Re-run the same config with the same seed → identical sequence
```

Replay records are additive and backward compatible. New records include optional metadata fields:

- `run_id` deterministic identifier derived from protocol plus canonicalized config
- `seed` seed used for generation (or `null`)
- `profile_name` optional campaign/profile label

Older JSONL records without these fields remain readable.

**Known limitation**: Replay does not restore UDS session/security state or J1939 connection state; exact response patterns may differ. `casic-replay-check` can report recognizable protocol-frame counts, but cannot infer accepted device state from sent-only captures.

## Observability Outputs

### Optional received-frame and transport-failure capture

All four fuzzers support `--save-responses` (default: **false**), with
`--responses-file <path>` selecting a JSONL output. A path alone does not enable
saving. YAML accepts the same settings globally or per protocol:

```yaml
global:
  save_responses: false
  response_drain_seconds: 0.1
protocols:
  udsic:
    enabled: true
    save_responses: true
    responses_file: .\replay\uds_responses.jsonl
```

This snippet is an addition to an existing interface/target configuration, not
a complete target profile. Each enabled protocol must have a distinct capture
path. Without an explicit path, the defaults are `cansic_responses.jsonl`,
`uds_responses.jsonl`, `j1939_responses.jsonl`, and `cosic_responses.jsonl` in the
working directory. Repeated runs overwrite the file; archive results first.
Capture paths must not overwrite replay input/output, summary, or correlation files.

The capture streams and flushes each event, including:

- `event: received`: every frame returned by the adapter, **before protocol
  filtering**, with `accepted`, CAN ID, hexadecimal payload, extended/FD flags,
  host receive timestamp, original adapter timestamp in `frame.meta.adapter_timestamp`,
  and receive metadata (error/remote-frame flags and DLC).
- `event: transport_error`: open/send/receive/close failures, exception type and
  message, operation, and the attempted frame for send failures.
- Common context: schema version, protocol, run ID, seed/profile, interface,
  bitrate, host observation time, and phase (`run`, `replay`, or `drain`).

`accepted` means a non-error, non-remote data frame passed the protocol filter,
not that it is a valid reply or came from the intended ECU. Captured
`frame_kind` distinguishes `data`, `can_error`, and `remote`; CAN error and
remote frames never enter response correlation or adaptive processing.
`observed_frames` counts all RX, `ordinary_received` counts data frames before
protocol filtering, and `received` counts accepted data frames. Separate
`can_error_frames` and `remote_frames` counts appear in summaries and health reports.
Old summaries lack these counts and cannot be retrospectively reclassified.

Receive `frame.timestamp` now uses host wall time at dequeue, in the same clock
domain as logged requests (`frame.meta.timestamp_source: host_receive`).
The original unmodified adapter value is retained in `frame.meta.adapter_timestamp`;
no guessed boot-time offset is applied. `observed_at` records capture write time.
Correlation latency therefore includes adapter/host queue and processing delays:
it is **host-observed latency**, not hardware response latency. Normalizing the
clock does not prove request/response causality or fix ambiguous/stale messages.
Existing captures are not rewritten. These files
are event logs, not sent-frame replay inputs.

When enabled, receive polling also runs for raw CAN, drains at most 256 frames
per generation, and listens for a bounded final window
(`response_drain_seconds`, default 0.1; range 0..60). This is best-effort capture,
not a continuous bus analyzer: traffic before/after a run or beyond adapter
buffer capacity can be missed. Additional polling and feedback can change the
subsequent UDS sequence even with the same seed. Saving also works during replay.

Transport failures are logged to the console and counted separately as
`transport_errors` in summaries and health reports even when saving is disabled.
`sent` remains an **attempt count**, not confirmed delivery. Active known-good
before/after probes and automatic device-failure confirmation are not implemented.

The local mixed SCIS profile's UDS section uses `rate_mode: 0`,
`uds_max_payload_len: 1`, and a two-second final receive drain for an initial
single-frame-sized campaign. Other sections retain their configured speeds.
Pacing reduces burst/queue pressure; it does not guarantee delivery or repair a
bus/ACK problem. Malformed PCI testing can still deliberately advertise invalid
lengths/types. Archive previous outputs before running again.

### Opt-in feedback for the other protocols

New feedback settings default to **0.0** (off), range 0..1. Existing UDS
sequence/NRC controls remain unchanged.

| Protocol | YAML / CLI | Feedback behavior |
|---|---|---|
| Raw CAN | `raw_feedback_probability` / `--raw-feedback-probability` | Learns up to 256 observed ID/format/payload templates and probabilistically mutates a template with the existing mutation engine. Explicit destination and FD permission are respected. This is traffic-guided mutation, not request/response inference. |
| CANopen | `canopen_feedback_probability` / `--canopen-feedback-probability` | Accepts the selected node's heartbeat/boot-up frames. Observed stopped/boot-up state biases toward an NMT pre-operational request; observed operational/pre-operational state biases toward SDO traffic. Reuses the existing temporary SDO-abort blacklist. |
| J1939 | `j1939_feedback_probability` / `--j1939-feedback-probability` | Tracks the latest addressed application transmission or RTS within `correlation_window_seconds`. Matching peer/destination/referenced-PGN ACK feedback biases the next selected generation toward that PGN/peer; negative ACK or TP Abort suppresses TP for that generation and changes the PGN when it is not explicitly pinned. |

For example, set `raw_feedback_probability: 0.25` under `cansic`,
`canopen_feedback_probability: 0.25` under `cosic`, or
`j1939_feedback_probability: 0.25` under `j1939sic`. Saving responses and enabling
feedback are independent choices. Generated feedback-driven frames carry a
`meta.feedback` tag in sent replay output.

CANopen already had optional abort-aware selection and local NMT-state
awareness; the new setting adds **observed** heartbeat feedback. Requested NMT
state is not proof of actual state. J1939 feedback does not implement a
CTS-paced transport client, complete address claiming, or response matching for
arbitrary broadcasts. Explicit PGN/address settings are not overridden.

### Summary JSON

Summary JSON is written only when enabled.

- Single protocol CLI: one-run summary payload
- YAML multi-protocol runner: one aggregate file written at run completion

Required run fields include:

- `protocol`, `run_id`, `seed`, `profile_name`
- `started_at`, `ended_at`, `duration_ms`
- `sent`, `received`, `errors`, `burst_frames`
- `transport_errors`, `observed_frames`, `ordinary_received`, `can_error_frames`, `remote_frames`

`sent` counts attempts; `received` counts data frames accepted by the protocol
filter, not validated replies. For current summaries,
`observed_frames = ordinary_received + can_error_frames + remote_frames`.
Error/remote frames never enter application feedback or correlation.
`errors` is the response-processing error count, not the CAN error-frame count.

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

### Offline health report

`casic-health-report` combines existing run-summary JSON and correlation CSV files into an offline JSON report. It does not open a CAN interface or contact a device:

```powershell
casic-health-report --summary .\casic_summary.json `
  --correlation .\uds_correlation.csv `
  --correlation .\j1939_correlation.csv `
  --output .\health-report.json
```

Repeat `--summary` or `--correlation` to include multiple artifacts. The report includes run counts, receive-to-send ratios, request match counts, unmatched percentages, and latency percentiles where correlation rows exist. These are diagnostic observations only: missing responses, errors, or latency changes do not prove that a device crashed or hung. Compare results with a known-good baseline and verify the device state independently.

To compare a current run with a previously generated health report, add `--baseline .\baseline-health.json`. Deltas are descriptive only; comparisons require one matching protocol and profile.

The YAML runner also creates a health report automatically when summary output is enabled. Configure `global.health_report_enabled: false` to disable it, or set `global.health_report_file` to choose its output path. By default, the report is written next to the summary using the summary filename with `_health` appended. YAML health reporting reads the summary and only those correlation CSVs enabled for successfully completed protocols; it sends no additional CAN frames.

### Offline replay validation and coverage

Use `casic-replay-check .\capture.jsonl` to validate an existing replay file without transmitting it. The checker reports malformed records and common identifier/payload/timestamp issues; it cannot establish protocol correctness or restore device state. See [docs/OFFLINE_VALIDATION_AND_COVERAGE.md](docs/OFFLINE_VALIDATION_AND_COVERAGE.md) for the implementation evidence matrix, replay limitations, and a manual lab-validation checklist.

The checker also summarizes recognizable state-changing UDS and CANopen frames and J1939 transport frames. This is a sequence inventory, not state reconstruction; never treat it as proof that the target accepted the request.

### Passive PCAN observation

`casic-pcan-check` passively listens to the PCAN channel from the YAML config for five seconds by default. It does not call the CAN transmit API or run any fuzzer:

```powershell
casic-pcan-check --config .\casic\examples\casic.yaml --duration 5 `
  --output .\replay\pcan-passive-check.json
```

The duration is limited to 1–60 seconds. The report lists observed CAN IDs and whether the configured UDS/CANopen response IDs appeared during that sample. No traffic or a missing ID is inconclusive; this is adapter/bus observation, not a device health verdict. Ensure the adapter supports passive/listen-only mode and confirm its driver state using the vendor's tooling if required.

### Interpreting Results

**Match rate**: Shows how many requests got responses
- ≥ 90% → Target is stable; fuzz harder
- 50–90% → Some protocol violations detected
- < 50% → Target is unstable; may have found critical bugs

**Latency percentiles** (`p50_ms`, `p90_ms`, `p99_ms`):
- Sudden spike in p99 → timeout or congestion detected
- Consistent high latency → potential firmware hang or backoff
- Usually: p50 < 10ms, p99 < 100ms on modern hardware

**Unmatched requests**
- Small number: Normal in high-fuzz scenarios
- Large number or increasing: Suggests state machine corruption

**For UDS**: Check if `invalid-sid-prob` or `malformed-pci-prob` correlates with unmatched responses → indicates stack does not recover from protocol errors

**For J1939**: Look for TP sequence anomaly patterns; if BAM logic breaks, expect connection timeouts

## Troubleshooting

**Interface not found**:
```bash
cansic -i can0 -r 1 -s rand -d rand -p100 -m10
# Error: can0 not found
```
On Linux: `ip link show` to verify interface exists, then `sudo ip link set can0 up type can bitrate 500000`

**Permission denied (SocketCAN)**:
```bash
sudo cansic -i can0 -r 1 -s rand -d rand -p100 -m10
```
On Linux: SocketCAN requires root or group membership in `can` group

**PCAN driver not found (Windows)**:
- Ensure PEAK PCAN-Basic drivers are installed from https://www.peak-system.com/
- Check Device Manager → Universal Serial Bus controllers for PCAN device
- Restart Python/terminal after driver installation

**Adapter unavailable / offline transport**:
```bash
CAN open failed on ...: ...
```
- Install `python-can`: `pip install -e .[can]`
- Verify interface name, driver, connection, and bitrate before active use.
- Frame generation may continue offline; `sent` does not prove delivery.

**PCAN transmit queue full**:
- This is a local send/enqueue failure, not a UDS negative response.
- Archive output first; select only the protocol on the verified port.
- Start UDS with `rate_mode: 0`, `uds_max_payload_len: 1`, and
  `response_drain_seconds: 2.0`. Malformed PCI testing may still produce invalid
  advertised types/lengths, but these settings avoid generated CF bursts.
- Check `transport_errors` and `can_error_frames` independently. Pacing is not
  an ACK/physical-layer repair and does not guarantee successful delivery.
- Standard and local SCIS initial UDS profiles use these settings; the in-depth
  profile deliberately retains maximum-speed multi-frame stress.

**Parser errors (CANopen)**:
```bash
cosic -i can0 -r 1 -s rand -d 0x600 -p100 -m10 --eds ./node.eds
# Warning: Missing attribute 'DataType' in object 0x1000
```
This is normal; parser uses defaults and logs warnings. If critical constraints are missing, dictionary file may be incomplete.

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
**Implemented**: Open/send/receive/close failures are logged and counted as
`transport_errors`, with optional streamed response/error capture.
CAN error frames have a separate count and do not enter application feedback.
Progress output includes transport and CAN-error counts.

**Remaining**: Confirmed on-wire delivery, queue-aware retry/backpressure,
fail-fast campaign policy, and independent device-health confirmation.
No automatic retry or recovery is implied by error visibility.

**Tests**: `test_response_capture.py` covers transport operations, receive
classification, capture output, and cross-clock-domain correlation.

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
