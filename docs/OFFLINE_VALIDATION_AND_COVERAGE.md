# Offline validation and project coverage

This document records what the current implementation and tests demonstrate, plus focused gaps for future work. It is not a claim of full standards conformance. All validation tooling described here operates on files and does not connect to a CAN interface.

## Replay fidelity and file validation

### What is implemented

- Replay is newline-delimited JSON containing protocol labels and sent `CANFrame` records.
- Newer records may include run ID, seed, profile name, note, and nested burst frame metadata; legacy records without the metadata remain supported.
- `casic-replay-check` validates JSONL syntax, required frame fields, CAN identifier bounds, payload bounds, timestamp types/order, burst metadata shape, and common protocol labels.
- Its protocol observations count UDS ISO-TP PCI/service bytes, J1939 PGNs/TP CM-DT frames, and CANopen NMT/SDO command families when recognizable from recorded frames. These are counts, not reconstructed device state.
- It flags likely state-changing UDS requests (for example session control, reset, security access, writes, and routine control), CANopen NMT commands/SDO downloads, and reports their frame identifiers and counts. This is sequence inventory only; sent-only records cannot establish successful state transitions or their later effects.
- Validation findings distinguish errors from warnings. A malformed capture returns a non-zero command status; warnings do not invalidate otherwise parseable records.

Run the checker without transmitting:

```powershell
casic-replay-check .\replay\cansic_from_yaml.jsonl
casic-replay-check .\replay\cansic_from_yaml.jsonl --output .\replay-check.json
```

### Known limits

- Replay files remain sent-frame logs. Optional `save_responses: true` writes a separate streamed JSONL event log of observed RX frames (including filtered-out frames) and transport failures. These event logs are not inputs to the replay checker and are not a complete continuous bidirectional trace.
- The checker verifies structure and common wire constraints, not protocol correctness or equivalence of a future replay.
- UDS session/security state and J1939 transport connection state are not reconstructed from a capture.
- The state-context section is explicitly marked incomplete because sent-only records cannot establish whether a device accepted a session change, security transition, or transport connection.
- The existing `--replay` behavior transmits frames. The offline checker intentionally does not invoke or change that behavior.

### Passive PCAN receive check

`casic-pcan-check --config .\casic\examples\casic.yaml --duration 5 --output .\replay\pcan-passive-check.json` opens the configured PCAN channel in python-can `BusState.PASSIVE` and receives frames for a bounded 1–60 second interval. The implementation makes no send calls and sets `receive_own_messages=False`. It reports a sample of observed identifiers and compares the sample with configured UDS and CANopen response IDs when present.

This only verifies that the PCAN channel can be opened in the requested passive state and whether any frames were observable during the short window. It does not send a probe, prove the target is present, identify which node produced a frame, or diagnose device health. Driver/hardware enforcement of listen-only behavior is adapter-dependent; consult the PCAN driver's diagnostics when independent confirmation is needed. No live hardware run is implied by unit tests.

## Protocol support and evidence matrix

Optional description imports are available via `pip install -e ".[descriptions]"`.
`UDSDescriptionParser` resolves ODX/PDX ECU variants/services and request constants with odxtools;
`J1939DescriptionParser` reads DBC messages/signals with cantools. These supply inspectable
metadata only, not automatic generation, transport configuration, state restoration, or standards
conformance. Test fixtures cover both formats and CLI/YAML wiring without opening an interface.
Samples are grouped in `casic/examples/uds`, `casic/examples/j1939`, and `casic/examples/canopen`.

| Area | Implemented in this codebase | Visible test evidence | Important gaps / qualification |
|---|---|---|---|
| Raw CAN (`cansic`) | Random or selected CAN IDs, classic/FD payload generation, mutation operators/chains, seedable generator | CLI/runtime controls, mutation and replay tests | No claim of full CAN/CAN-FD controller conformance; hardware may constrain IDs, DLCs, timing, and error-frame behavior |
| UDS / ISO-TP (`udsic`) | Service selection, single/multi-frame generation, sequence and NRC awareness, local adaptive behavior, selected length/sequence anomalies | UDS awareness and CLI tests | No complete ISO 14229 service model, ECU-specific data dictionary, or faithful ISO-TP flow-control/timing simulation established by current tests; local state is not restored from replay |
| SAE J1939 (`j1939sic`) | 29-bit identifier construction, PGN/address fields, TP CM/DT bursts, selectable sequencing/order/count variants | J1939 TP tests and CLI/runtime tests | No complete J1939 parameter database or full network-management/connection state model established by current tests; timing metadata is not evidence that hardware timing was applied |
| CANopen (`cosic`) | SDO/PDO/NMT/EMCY/SYNC/TIME frame families; EDS and selected XDD/XDC parsing; dictionary-aware choices and local NMT/abort adaptation | CANopen constraints, parser, and CLI tests, including namespaced XDD and EDS metadata fixtures | Parser supports a practical subset; vendor extensions, full object semantics, complete PDO mapping/communication parameters, and all segmented transfer state require broader fixtures and validation |
| Shared observation | Run summaries, attempted-send/accepted-receive counts, separate transport-error counts, optional all-observed RX/error JSONL, CSV correlation for UDS/J1939, offline reports | Reporting, capture, replay, orchestrator, and health-report tests | Capture is best-effort and bounded to the run/final drain; missing traffic is not proof of failure; active baseline/post-run probes and independent recovery evidence remain absent |

Opt-in raw CAN traffic-template mutation, CANopen heartbeat/abort feedback, and
J1939 addressed ACK/negative-ACK/TP-Abort feedback are covered by offline fake-bus
and protocol tests. The new probabilities default to zero. See the README for
configuration and precise limitations; no live validation or full transport
state-machine conformance is implied.

Receive counters distinguish all observed frames, ordinary data frames before
filtering, accepted application data (`received`), CAN error frames, and remote
frames. CAN error/remote frames remain in optional captures but do not enter
application correlation or feedback. Summaries and health reports expose bus
error observations independently of adapter-operation failures.

Live transport receive timestamps use host dequeue wall time for comparison
with request timestamps. The original adapter timestamp is preserved in frame
metadata. Latencies include buffering/processing delays and do not establish
hardware response timing; old captures and summary counts are not repaired.

“Visible test evidence” means there are tests in the repository for the named behavior; it does not mean conformance across all devices, adapters, or standards editions. Gaps are phrased as unestablished coverage, not proof that no related code exists.

## Manual hardware-validation checklist

Use the device owner's approved procedure and a controlled bench. This checklist is for human-led verification; it does not authorize or automate traffic generation.

### Before connecting

- Record device model/revision, firmware, adapter model/driver, host OS, interface settings, bus bitrate, and any termination/topology details.
- Confirm written authorization, test ownership, recovery contact, and a known-good firmware/configuration backup.
- Isolate the bench from production equipment and unrelated CAN nodes. Confirm that unintended actuators or hazardous outputs cannot be energized.
- Agree on a conservative, finite test envelope and explicit stop conditions with the device owner before any active test.
- Verify that emergency stop, power isolation, and a documented reset/recovery route are accessible to the operator.

### Establish the baseline

- Confirm adapter/interface operation using the vendor's passive or approved diagnostic method.
- Capture a known-good idle/normal-operation observation and document expected traffic and device indicators.
- Run the existing offline replay checker and health reporter on prior artifacts, when available, to verify the analysis pipeline before testing.
- Record baseline device health indicators and operator-visible behavior so comparisons are meaningful.

### During an approved validation session

- Keep a human operator present; observe device status, bus state, adapter diagnostics, and independent health indicators.
- Stop immediately on unexpected actuation, loss of bus communication, repeated adapter/bus errors, device reset, abnormal heating/noise, or any agreed stop condition.
- Do not automatically retry, recover, or restart a device while a test is in progress; follow the owner's manual recovery procedure after the test is stopped.
- Preserve the exact configuration, seed/profile, start/end time, logs, adapter diagnostics, and operator notes for each run.

### After the session

- Confirm device behavior and required functions using the owner's approved checks; do not infer recovery solely from a new response on the bus.
- Compare captured metrics to the baseline. Treat changes as investigation leads, not proof of failure.
- Record whether the test stopped normally, encountered an operator stop, adapter fault, device reset, or other observation; keep device outcome distinct from tool outcome.
- Retain artifacts with a run ID and document any manual reset or configuration restoration.

## Offline result comparison and triage

The health report can compare a new run with a previously generated health-report JSON:

```powershell
casic-health-report --summary .\current-summary.json `
  --correlation .\current-uds-correlation.csv `
  --baseline .\baseline-health.json `
  --output .\current-health.json
```

Comparison matches runs by protocol and profile name. If there is not exactly one baseline match, the report marks that run `not_comparable` instead of guessing. For matched runs, it reports current-minus-baseline deltas for receive ratio, errors per 1,000 sent, duration, unmatched request percentage, and available latency percentiles. It adds review signals for observed increases/decreases, but applies no pass/fail threshold and does not rank these as confirmed defects.

Runs also include triage signals for zero counted receives, recorded run errors, unavailable correlation, and unmatched requests. These are prompts for human review, not diagnoses.

Suggested human review order:

1. Check parse/transport errors and whether the capture itself is complete.
2. Compare receive and unmatched-response metrics only against a baseline with the same device, adapter, profile, and comparable operating conditions.
3. Review latency percentile changes alongside request mix and bus load.
4. Corroborate any suspected device issue with independent device indicators and operator observations.
5. Preserve the original inputs and report; do not label a suspected defect confirmed until independently reproduced and reviewed.
