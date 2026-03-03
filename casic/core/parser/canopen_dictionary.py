from __future__ import annotations

import configparser
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from casic.core.models import CANopenDictionary, DictionaryEntry


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        return int(text, 16)
    if re.match(r"^[0-9a-fA-F]+h$", text):
        return int(text[:-1], 16)
    return int(text)


class CANopenDictionaryParser:
    def load(self, file_path: str | Path) -> CANopenDictionary:
        path = Path(file_path)
        suffix = path.suffix.lower()
        if suffix == ".eds":
            return self._load_eds(path)
        if suffix in {".xdd", ".xdc"}:
            return self._load_xml(path)
        raise ValueError(f"Unsupported dictionary type: {suffix}")

    def _load_eds(self, path: Path) -> CANopenDictionary:
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read(path, encoding="utf-8")

        dictionary = CANopenDictionary()
        for section in parser.sections():
            if re.match(r"^[0-9A-Fa-f]{4}(sub[0-9A-Fa-f]{1,2})?$", section):
                entry = self._eds_section_to_entry(section, parser[section])
                if entry:
                    dictionary.entries.append(entry)

            if section in {"1400", "1401", "1402", "1403", "1800", "1801", "1802", "1803", "1200", "1280"}:
                cob_id = _parse_int(parser[section].get("COB-ID"))
                if cob_id is not None:
                    dictionary.cob_ids[section] = cob_id

        self._infer_cob_ids(dictionary)
        self._infer_pdo_mapping(dictionary)
        return dictionary

    def _eds_section_to_entry(self, section: str, data) -> DictionaryEntry | None:
        split = section.lower().split("sub")
        index = int(split[0], 16)
        subindex = int(split[1], 16) if len(split) == 2 else 0
        name = data.get("ParameterName", f"{section}")
        data_type = data.get("DataType", "UNKNOWN")
        access_type = data.get("AccessType", "rw")
        return DictionaryEntry(
            index=index,
            subindex=subindex,
            name=name,
            data_type=data_type,
            access_type=access_type,
            default_value=data.get("DefaultValue"),
            low_limit=data.get("LowLimit"),
            high_limit=data.get("HighLimit"),
            pdo_mapping=(data.get("PDOMapping", "0") in {"1", "yes", "true", "True"}),
            metadata=dict(data.items()),
        )

    def _load_xml(self, path: Path) -> CANopenDictionary:
        tree = ET.parse(path)
        root = tree.getroot()
        dictionary = CANopenDictionary()
        namespaces = {"x": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}

        objects = list(root.findall(".//Object"))
        if "x" in namespaces:
            objects.extend(root.findall(".//x:Object", namespaces))

        for obj in objects:
                index = _parse_int(obj.get("index") or obj.get("Index"))
                if index is None:
                    continue

                subobjects = list(obj.findall("SubObject"))
                if "x" in namespaces:
                    subobjects.extend(obj.findall("x:SubObject", namespaces))
                if not subobjects:
                    dictionary.entries.append(
                        DictionaryEntry(
                            index=index,
                            subindex=0,
                            name=obj.get("name") or obj.get("Name") or f"0x{index:04X}",
                            data_type=obj.get("dataType") or obj.get("DataType") or "UNKNOWN",
                            access_type=obj.get("accessType") or obj.get("AccessType") or "rw",
                            low_limit=obj.get("lowLimit") or obj.get("LowLimit"),
                            high_limit=obj.get("highLimit") or obj.get("HighLimit"),
                            metadata=obj.attrib,
                        )
                    )
                    continue

                for sub in subobjects:
                    subindex = _parse_int(sub.get("subIndex") or sub.get("SubIndex")) or 0
                    dictionary.entries.append(
                        DictionaryEntry(
                            index=index,
                            subindex=subindex,
                            name=sub.get("name") or sub.get("Name") or f"0x{index:04X}:{subindex}",
                            data_type=sub.get("dataType") or sub.get("DataType") or "UNKNOWN",
                            access_type=sub.get("accessType") or sub.get("AccessType") or "rw",
                            low_limit=sub.get("lowLimit") or sub.get("LowLimit"),
                            high_limit=sub.get("highLimit") or sub.get("HighLimit"),
                            metadata=sub.attrib,
                        )
                    )

        comm_objects = list(root.findall(".//CommunicationObject"))
        if "x" in namespaces:
            comm_objects.extend(root.findall(".//x:CommunicationObject", namespaces))

        for comm in comm_objects:
            name = comm.get("name") or comm.get("Name") or "comm"
            cob_id = _parse_int(comm.get("cobId") or comm.get("CobId") or comm.get("COB-ID"))
            if cob_id is not None:
                dictionary.cob_ids[name] = cob_id

        self._infer_cob_ids(dictionary)
        self._infer_pdo_mapping(dictionary)
        return dictionary

    def _infer_cob_ids(self, dictionary: CANopenDictionary):
        if not dictionary.cob_ids:
            dictionary.cob_ids["NMT"] = 0x000
            dictionary.cob_ids["SYNC"] = 0x080
            dictionary.cob_ids["TIME"] = 0x100
            dictionary.cob_ids["EMCY"] = 0x080
            dictionary.cob_ids["SDO_RX"] = 0x600
            dictionary.cob_ids["SDO_TX"] = 0x580
            dictionary.cob_ids["TPDO1"] = 0x180
            dictionary.cob_ids["RPDO1"] = 0x200
        else:
            dictionary.cob_ids.setdefault("SDO_RX", 0x600)
            dictionary.cob_ids.setdefault("SDO_TX", 0x580)
            dictionary.cob_ids.setdefault("TPDO1", 0x180)
            dictionary.cob_ids.setdefault("RPDO1", 0x200)

    def _infer_pdo_mapping(self, dictionary: CANopenDictionary):
        mapped = [(entry.index, entry.subindex) for entry in dictionary.entries if entry.pdo_mapping]
        if mapped:
            dictionary.pdo_mappings.setdefault("TPDO1", mapped[:8])
