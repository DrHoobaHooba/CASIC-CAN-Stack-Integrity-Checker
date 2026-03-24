from __future__ import annotations

from casic.core.engine import BaseFuzzer
from casic.core.models import CANFrame, CANopenDictionary, DictionaryEntry


class CANopenFuzzer(BaseFuzzer):
    protocol_name = "cosic"
    _DATA_TYPE_SIZE_BYTES = {
        0x0001: 1,  # BOOLEAN
        0x0002: 1,  # INTEGER8
        0x0003: 2,  # INTEGER16
        0x0004: 4,  # INTEGER32
        0x0005: 1,  # UNSIGNED8
        0x0006: 2,  # UNSIGNED16
        0x0007: 4,  # UNSIGNED32
        0x0008: 4,  # REAL32
        0x0010: 3,  # VISIBLE_STRING (sample bytes)
        0x0015: 8,  # INTEGER64
        0x001B: 8,  # UNSIGNED64
    }

    def __init__(self, config, dictionary: CANopenDictionary | None = None):
        super().__init__(config)
        self.dictionary = dictionary or CANopenDictionary()
        self._entries_by_key = {
            (entry.index, entry.subindex): entry for entry in self.dictionary.entries
        }
        self._abort_blacklist: dict[tuple[int, int], int] = {}
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
        if self.config.canopen_abort_aware_probability > 0.0:
            candidates = [
                entry
                for entry in self.dictionary.entries
                if self._abort_blacklist.get((entry.index, entry.subindex), 0) <= 0
            ]
            if candidates:
                return self.rng.choice(candidates)
        return self.rng.choice(self.dictionary.entries)

    def should_accept_response(self, frame: CANFrame) -> bool:
        sdo_tx_cobid = self._resolve_cob_id("SDO_TX", 0x580)
        return frame.can_id == sdo_tx_cobid

    def _decay_abort_blacklist(self):
        expired: list[tuple[int, int]] = []
        for key, remaining in self._abort_blacklist.items():
            next_value = remaining - 1
            if next_value <= 0:
                expired.append(key)
            else:
                self._abort_blacklist[key] = next_value
        for key in expired:
            self._abort_blacklist.pop(key, None)

    def on_response(self, frame: CANFrame):
        if len(frame.data) < 8:
            return
        if frame.data[0] != 0x80:
            return
        if self.rng.random() >= self.config.canopen_abort_aware_probability:
            return

        index = frame.data[1] | (frame.data[2] << 8)
        subindex = frame.data[3]
        abort_code = int.from_bytes(frame.data[4:8], byteorder="little", signed=False)

        # Common abort-code classes where retrying the same object is low-value.
        if abort_code in {
            0x05040000,
            0x06010000,
            0x06010001,
            0x06010002,
            0x06020000,
            0x06090011,
            0x06090030,
            0x08000000,
        }:
            self._abort_blacklist[(index, subindex)] = self.config.canopen_abort_blacklist_window

    def _parse_optional_int(self, text: str | None) -> int | None:
        if text is None:
            return None
        value = str(text).strip()
        if not value:
            return None
        if value.lower().startswith("0x"):
            return int(value, 16)
        if value.lower().endswith("h"):
            return int(value[:-1], 16)
        return int(value)

    def _pick_sdo_command(self, entry: DictionaryEntry | None) -> int:
        if entry is None:
            return self.rng.choice([0x40, 0x2F, 0x2B, 0x23])

        access = entry.access_type.lower()
        write_commands = [0x2F, 0x2B, 0x23]
        if "wo" in access:
            return self.rng.choice(write_commands)
        if "ro" in access or "const" in access:
            return 0x40
        if "rw" in access:
            return self.rng.choice([0x40] + write_commands)
        return self.rng.choice([0x40, 0x2F, 0x2B, 0x23])

    def _generate_value(self, entry: DictionaryEntry | None, command: int) -> bytes:
        if command == 0x40 or entry is None:
            return self.rng.randbytes(4)

        low = self._parse_optional_int(entry.low_limit)
        high = self._parse_optional_int(entry.high_limit)
        if low is not None and high is not None and low <= high:
            value = self.rng.randint(low, high)
            value = max(0, min(value, 0xFFFFFFFF))
            return value.to_bytes(4, byteorder="little", signed=False)
        return self.rng.randbytes(4)

    def _entry_size_bytes(self, entry: DictionaryEntry | None) -> int:
        if entry is None:
            return 1
        data_type = self._parse_optional_int(entry.data_type)
        if data_type is None:
            return 1
        return self._DATA_TYPE_SIZE_BYTES.get(data_type, 1)

    def _generate_sdo(self) -> CANFrame:
        cob_id = self._resolve_cob_id("SDO_RX", 0x600)
        entry = self._random_dictionary_entry()

        if entry is None:
            idx = self.rng.randint(0x1000, 0x2FFF)
            sub = self.rng.randint(0, 0xFF)
        else:
            idx = entry.index
            sub = entry.subindex

        command = self._pick_sdo_command(entry)
        if self.rng.random() < self.config.canopen_invalid_sdo_probability:
            command = self.rng.choice([0x00, 0x7F, 0xFF, 0x10])
        value = self._generate_value(entry, command)
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
        for index, sub in mappings:
            if len(payload) >= 8:
                break
            entry = self._entries_by_key.get((index, sub))
            if entry is not None and not entry.pdo_mapping:
                continue
            size = max(1, min(self._entry_size_bytes(entry), 8 - len(payload)))
            payload.extend(self.rng.randbytes(size))
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
        self._decay_abort_blacklist()
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
