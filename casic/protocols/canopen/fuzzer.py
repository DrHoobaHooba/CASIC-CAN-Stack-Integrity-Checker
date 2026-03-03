from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame, CANopenDictionary, DictionaryEntry


class CANopenFuzzer(BaseFuzzer):
    protocol_name = "cosic"

    def __init__(self, config, dictionary: CANopenDictionary | None = None):
        super().__init__(config)
        self.dictionary = dictionary or CANopenDictionary()
        self.node_id = config.node_id
        self.destination_cobid = None
        if config.destination != "rand":
            self.destination_cobid = int(config.destination, 0)

        if self.node_id is None:
            if config.sdo_rx_cobid is not None and 0x600 <= config.sdo_rx_cobid <= 0x67F:
                self.node_id = config.sdo_rx_cobid - 0x600
            elif self.destination_cobid is not None and 0x600 <= self.destination_cobid <= 0x67F:
                self.node_id = self.destination_cobid - 0x600

    def _resolve_cob_id(self, key: str, default: int) -> int:
        explicit = {
            "SDO_RX": self.config.sdo_rx_cobid,
            "SDO_TX": self.config.sdo_tx_cobid,
            "TPDO1": self.config.tpdo1_cobid,
            "RPDO1": self.config.rpdo1_cobid,
        }.get(key)
        if explicit is not None:
            return explicit

        if key == "SDO_RX" and self.destination_cobid is not None:
            return self.destination_cobid

        if self.node_id is not None:
            if key == "SDO_RX":
                return 0x600 + self.node_id
            if key == "SDO_TX":
                return 0x580 + self.node_id
            if key == "TPDO1":
                return 0x180 + self.node_id
            if key == "RPDO1":
                return 0x200 + self.node_id
            if key == "EMCY":
                return 0x080 + self.node_id

        return self.dictionary.cob_ids.get(key, default)

    def _random_dictionary_entry(self) -> DictionaryEntry | None:
        if not self.dictionary.entries:
            return None
        return self.rng.choice(self.dictionary.entries)

    def _generate_sdo(self) -> CANFrame:
        cob_id = self._resolve_cob_id("SDO_RX", 0x600)
        entry = self._random_dictionary_entry()

        if entry is None:
            idx = self.rng.randint(0x1000, 0x2FFF)
            sub = self.rng.randint(0, 0xFF)
        else:
            idx = entry.index
            sub = entry.subindex

        command = self.rng.choice([0x40, 0x2F, 0x2B, 0x23])
        if self.rng.random() < self.config.canopen_invalid_sdo_probability:
            command = self.rng.choice([0x00, 0x7F, 0xFF, 0x10])
        value = self.rng.randbytes(4)
        if self.rng.random() < self.config.canopen_invalid_sdo_probability:
            sub = self.rng.choice([0xFF, 0x80, 0x7F])
        data = bytes([command, idx & 0xFF, (idx >> 8) & 0xFF, sub]) + value
        return CANFrame(can_id=cob_id, data=data)

    def _generate_pdo(self) -> CANFrame:
        pdo_id = self._resolve_cob_id("TPDO1", 0x180)
        mappings = self.dictionary.pdo_mappings.get("TPDO1", [])
        if not mappings:
            return CANFrame(can_id=pdo_id, data=self.rng.randbytes(8))

        payload = bytearray()
        for _index, _sub in mappings[:8]:
            payload.append(self.rng.randint(0, 255))
        return CANFrame(can_id=pdo_id, data=bytes(payload).ljust(8, b"\x00"))

    def _generate_nmt(self) -> CANFrame:
        command = self.rng.choice([0x01, 0x02, 0x80, 0x81, 0x82])
        node_id = self.node_id if self.node_id is not None else self.rng.randint(0, 127)
        return CANFrame(can_id=0x000, data=bytes([command, node_id]))

    def _generate_emcy(self) -> CANFrame:
        cob_id = self._resolve_cob_id("EMCY", 0x080)
        code = self.rng.randint(0, 0xFFFF)
        register = self.rng.randint(0, 0xFF)
        manufacturer = self.rng.randbytes(5)
        payload = bytes([code & 0xFF, (code >> 8) & 0xFF, register]) + manufacturer
        return CANFrame(can_id=cob_id, data=payload)

    def _generate_sync_or_time(self) -> CANFrame:
        if self.rng.random() < 0.5:
            return CANFrame(can_id=0x080, data=b"")
        return CANFrame(can_id=0x100, data=self.rng.randbytes(6))

    def generate_frame(self, sequence_number: int) -> CANFrame:
        bias = self.config.canopen_mode_bias or "balanced"
        if bias == "sdo-heavy":
            mode = self.rng.choice(["sdo", "sdo", "sdo", "pdo", "nmt", "emcy", "sync_time"])
        elif bias == "pdo-heavy":
            mode = self.rng.choice(["pdo", "pdo", "pdo", "sdo", "nmt", "emcy", "sync_time"])
        elif bias == "control-heavy":
            mode = self.rng.choice(["nmt", "nmt", "emcy", "sync_time", "sdo", "pdo"])
        else:
            mode = self.rng.choice(["sdo", "pdo", "nmt", "emcy", "sync_time"])
        if mode == "sdo":
            return self._generate_sdo()
        if mode == "pdo":
            return self._generate_pdo()
        if mode == "nmt":
            return self._generate_nmt()
        if mode == "emcy":
            return self._generate_emcy()
        return self._generate_sync_or_time()
