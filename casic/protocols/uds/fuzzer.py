from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame


class UDSFuzzer(BaseFuzzer):
    protocol_name = "uds"

    def __init__(self, config):
        super().__init__(config)
        self._session_active = False
        self._security_unlocked = False
        self._pending_security_key_subfunction: int | None = None
        self._last_negative_response: tuple[int, int] | None = None
        self._last_positive_request_sid: int | None = None
        self._consecutive_negative_responses = 0

    def _mismatched_length(self, actual_length: int, minimum: int, maximum: int) -> int:
        candidates = [value for value in range(minimum, maximum + 1) if value != actual_length]
        if not candidates:
            return actual_length
        return self.rng.choice(candidates)

    def _extract_uds_payload(self, frame: CANFrame) -> bytes:
        if not frame.data:
            return b""
        pci_type = (frame.data[0] >> 4) & 0x0F
        if pci_type == 0:
            payload_len = frame.data[0] & 0x0F
            if payload_len <= 0:
                return b""
            return bytes(frame.data[1 : 1 + payload_len])
        return bytes(frame.data[1:])

    def _build_stateful_service(self) -> tuple[int, int, bytes]:
        if self._pending_security_key_subfunction is not None:
            subfunction = self._pending_security_key_subfunction
            self._pending_security_key_subfunction = None
            return (0x27, subfunction, self.rng.randbytes(4))

        if not self._session_active:
            return (0x10, self.rng.choice([0x01, 0x02, 0x03]), b"")

        if not self._security_unlocked:
            return (0x27, self.rng.choice([0x01, 0x03, 0x05]), b"")

        return (self.rng.choice([0x22, 0x2E, 0x31, 0x34, 0x36]), self.rng.randint(0, 0xFF), b"")

    def _build_negative_response_followup(self) -> tuple[int, int, bytes] | None:
        if self._last_negative_response is None:
            return None

        request_sid, nrc = self._last_negative_response

        if nrc == 0x78:
            return (request_sid, self.rng.randint(0, 0xFF), b"")

        if nrc in {0x33, 0x35, 0x36, 0x37}:
            self._security_unlocked = False
            self._pending_security_key_subfunction = None
            return (0x27, self.rng.choice([0x01, 0x03, 0x05]), b"")

        if nrc in {0x12, 0x31, 0x7E, 0x7F}:
            return (0x10, self.rng.choice([0x01, 0x02, 0x03]), b"")

        return None

    def _build_adaptive_service(self) -> tuple[int, int, bytes] | None:
        if self._consecutive_negative_responses > 0:
            if self.rng.random() < self.config.uds_nrc_backoff_probability:
                return (0x10, self.rng.choice([0x01, 0x02, 0x03]), b"")

            if self._last_negative_response is not None:
                request_sid, nrc = self._last_negative_response
                if nrc in {0x33, 0x35, 0x36, 0x37}:
                    return (0x27, self.rng.choice([0x01, 0x03, 0x05]), b"")
                if nrc == 0x78:
                    return (request_sid, self.rng.randint(0, 0xFF), b"")

        if self._last_positive_request_sid is not None:
            sid = self._last_positive_request_sid
            if sid == 0x10:
                return (0x22, self.rng.randint(0, 0xFF), b"")
            if sid == 0x27:
                return (0x27, self.rng.choice([0x01, 0x03, 0x05]), b"")
            return (sid, self.rng.randint(0, 0xFF), b"")

        return None

    def _build_recovery_probe(self) -> tuple[int, int, bytes] | None:
        if self._last_negative_response is not None:
            request_sid, nrc = self._last_negative_response
            if nrc in {0x33, 0x35, 0x36, 0x37}:
                return (0x10, self.rng.choice([0x01, 0x02, 0x03]), b"")
            if nrc in {0x12, 0x31, 0x7E, 0x7F}:
                return (0x3E, 0x00, b"")
            if nrc == 0x78:
                return (request_sid, 0x00, b"")

        if self._session_active and not self._security_unlocked:
            return (0x3E, 0x00, b"")

        if self._security_unlocked:
            return (0x22, self.rng.randint(0, 0xFF), b"")

        return None

    def _apply_cf_sequence_anomaly(self, burst_frames: list[CANFrame]) -> str | None:
        if len(burst_frames) < 2:
            return None
        if self.rng.random() >= self.config.uds_consecutive_frame_sequence_anomaly_probability:
            return None

        anomaly = self.rng.choice(["gap", "duplicate", "restart"])
        index = self.rng.randint(1, len(burst_frames) - 1)
        previous_seq = burst_frames[index - 1].data[0] & 0x0F

        if anomaly == "gap":
            seq = ((burst_frames[index].data[0] & 0x0F) + 1) & 0x0F
        elif anomaly == "duplicate":
            seq = previous_seq
        else:
            seq = 1

        burst_frames[index] = CANFrame(
            can_id=burst_frames[index].can_id,
            data=bytes([(0x20 | seq)]) + burst_frames[index].data[1:],
            is_extended_id=burst_frames[index].is_extended_id,
            is_fd=burst_frames[index].is_fd,
            timestamp=burst_frames[index].timestamp,
            meta=dict(burst_frames[index].meta),
        )
        return anomaly

    def should_accept_response(self, frame: CANFrame) -> bool:
        if self.config.uds_response_id is None:
            return True
        return frame.can_id == self.config.uds_response_id

    def on_response(self, frame: CANFrame):
        payload = self._extract_uds_payload(frame)
        if not payload:
            return

        sid = payload[0]
        if sid == 0x7F and len(payload) >= 3:
            self._last_negative_response = (payload[1], payload[2])
            self._consecutive_negative_responses += 1
            if payload[2] in {0x33, 0x35, 0x36, 0x37}:
                self._security_unlocked = False
            return

        if sid < 0x40:
            return

        request_sid = sid - 0x40
        self._last_negative_response = None
        self._last_positive_request_sid = request_sid
        self._consecutive_negative_responses = 0

        if request_sid == 0x10:
            self._session_active = True
            return

        if request_sid == 0x27 and len(payload) >= 2:
            subfunction = payload[1]
            if subfunction & 0x01:
                if subfunction < 0x7F:
                    self._pending_security_key_subfunction = subfunction + 1
            else:
                self._security_unlocked = True
                self._pending_security_key_subfunction = None

    def generate_frame(self, sequence_number: int) -> CANFrame:
        if self.config.uds_request_id is not None:
            dst_id = self.config.uds_request_id
        else:
            dst_id = self.rng.can_id() if self.config.destination == "rand" else int(self.config.destination, 0)

        sid: int
        subfunction: int
        extra_payload = b""

        if (
            self.rng.random() < self.config.uds_adaptive_sequence_probability
        ):
            adaptive = self._build_adaptive_service()
            if adaptive is not None:
                sid, subfunction, extra_payload = adaptive
            elif self.rng.random() < self.config.uds_recovery_probe_probability:
                probe = self._build_recovery_probe()
                if probe is not None:
                    sid, subfunction, extra_payload = probe
                else:
                    sid = self.rng.uds_sid()
                    subfunction = self.rng.randint(0, 0xFF)
            elif (
                self.rng.random() < self.config.uds_negative_response_awareness_probability
                and self._last_negative_response is not None
            ):
                followup = self._build_negative_response_followup()
                if followup is not None:
                    sid, subfunction, extra_payload = followup
                else:
                    sid = self.rng.uds_sid()
                    subfunction = self.rng.randint(0, 0xFF)
            elif self.rng.random() < self.config.uds_sequence_awareness_probability:
                sid, subfunction, extra_payload = self._build_stateful_service()
            elif self.rng.random() < self.config.uds_invalid_sid_probability:
                sid = self.rng.choice([0x00, 0xFF, 0x7F])
                subfunction = self.rng.randint(0, 0xFF)
            else:
                sid = self.rng.uds_sid()
                subfunction = self.rng.randint(0, 0xFF)
        elif (
            self.rng.random() < self.config.uds_recovery_probe_probability
        ):
            probe = self._build_recovery_probe()
            if probe is not None:
                sid, subfunction, extra_payload = probe
            else:
                sid = self.rng.uds_sid()
                subfunction = self.rng.randint(0, 0xFF)
        elif (
            self.rng.random() < self.config.uds_negative_response_awareness_probability
            and self._last_negative_response is not None
        ):
            followup = self._build_negative_response_followup()
            if followup is not None:
                sid, subfunction, extra_payload = followup
            else:
                sid = self.rng.uds_sid()
                subfunction = self.rng.randint(0, 0xFF)
        elif self.rng.random() < self.config.uds_sequence_awareness_probability:
            sid, subfunction, extra_payload = self._build_stateful_service()
        elif self.rng.random() < self.config.uds_invalid_sid_probability:
            sid = self.rng.choice([0x00, 0xFF, 0x7F])
            subfunction = self.rng.randint(0, 0xFF)
        else:
            sid = self.rng.uds_sid()
            subfunction = self.rng.randint(0, 0xFF)

        payload_len = self.rng.randint(0, max(0, self.config.uds_max_payload_len))
        app_payload = bytes([sid, subfunction]) + extra_payload + self.rng.randbytes(payload_len)

        if len(app_payload) <= 7:
            advertised_length = len(app_payload)
            mismatch = None
            if self.rng.random() < self.config.uds_single_frame_length_mismatch_probability:
                advertised_length = self._mismatched_length(len(app_payload), 1, 7)
                mismatch = "single-frame"
            pci = bytes([advertised_length])
            if self.rng.random() < self.config.uds_malformed_pci_probability:
                pci = bytes([self.rng.choice([0xFF, 0x7F, 0x00])])
            payload = (pci + app_payload).ljust(8, b"\x00")
            meta = {"uds_length_mismatch": mismatch} if mismatch is not None else {}
            return CANFrame(can_id=dst_id, data=payload, meta=meta)

        total_len = len(app_payload)
        advertised_total_len = total_len
        length_mismatch = None
        if self.rng.random() < self.config.uds_first_frame_length_mismatch_probability:
            advertised_total_len = self._mismatched_length(total_len, 8, min(self.config.uds_max_payload_len + 8, 0xFFF))
            length_mismatch = "first-frame"
        ff_header = bytes([(0x10 | ((advertised_total_len >> 8) & 0x0F)), advertised_total_len & 0xFF])
        if self.rng.random() < self.config.uds_malformed_pci_probability:
            ff_header = bytes([self.rng.choice([0x00, 0x2F, 0x3F]), ff_header[1]])
        ff = ff_header + app_payload[:6]
        burst_frames: list[CANFrame] = []

        seq = 1
        remaining = app_payload[6:]
        while remaining:
            chunk, remaining = remaining[:7], remaining[7:]
            cf_header = 0x20 | (seq & 0x0F)
            if self.rng.random() < self.config.uds_malformed_pci_probability:
                cf_header = self.rng.choice([0x00, 0x10, 0x30, 0xFF])
            cf = bytes([cf_header]) + chunk
            burst_frames.append(CANFrame(can_id=dst_id, data=cf.ljust(8, b"\x00")))
            seq = (seq + 1) & 0x0F
        cf_anomaly = self._apply_cf_sequence_anomaly(burst_frames)
        meta = {"burst": burst_frames}
        if length_mismatch is not None:
            meta["uds_length_mismatch"] = length_mismatch
        if cf_anomaly is not None:
            meta["uds_cf_sequence_anomaly"] = cf_anomaly
        return CANFrame(can_id=dst_id, data=ff.ljust(8, b"\x00"), meta=meta)
