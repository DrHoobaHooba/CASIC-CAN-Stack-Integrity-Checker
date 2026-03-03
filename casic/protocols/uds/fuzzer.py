from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame


class UDSFuzzer(BaseFuzzer):
    protocol_name = "uds"

    def should_accept_response(self, frame: CANFrame) -> bool:
        if self.config.uds_response_id is None:
            return True
        return frame.can_id == self.config.uds_response_id

    def generate_frame(self, sequence_number: int) -> CANFrame:
        if self.config.uds_request_id is not None:
            dst_id = self.config.uds_request_id
        else:
            dst_id = self.rng.can_id() if self.config.destination == "rand" else int(self.config.destination, 0)
        if self.rng.random() < self.config.uds_invalid_sid_probability:
            sid = self.rng.choice([0x00, 0xFF, 0x7F])
        else:
            sid = self.rng.uds_sid()
        subfunction = self.rng.randint(0, 0xFF)
        payload_len = self.rng.randint(0, max(0, self.config.uds_max_payload_len))
        app_payload = bytes([sid, subfunction]) + self.rng.randbytes(payload_len)

        if len(app_payload) <= 7:
            pci = bytes([len(app_payload)])
            if self.rng.random() < self.config.uds_malformed_pci_probability:
                pci = bytes([self.rng.choice([0xFF, 0x7F, 0x00])])
            payload = (pci + app_payload).ljust(8, b"\x00")
            return CANFrame(can_id=dst_id, data=payload)

        total_len = len(app_payload)
        ff_header = bytes([(0x10 | ((total_len >> 8) & 0x0F)), total_len & 0xFF])
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
        return CANFrame(can_id=dst_id, data=ff.ljust(8, b"\x00"), meta={"burst": burst_frames})
