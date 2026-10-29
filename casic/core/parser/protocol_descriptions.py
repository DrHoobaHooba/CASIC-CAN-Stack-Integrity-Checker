from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import zipfile


@dataclass(slots=True)
class UDSServiceDescription:
    name: str
    request_name: str
    service_id: int | None
    constants: dict[str, int | str]


@dataclass(slots=True)
class UDSDescription:
    source: str
    variant: str
    available_variants: list[str]
    services: list[UDSServiceDescription]
    limitations: list[str] = field(default_factory=lambda: [
        "Description metadata only; addresses, timing, security algorithms and requests are not applied automatically.",
        "Only directly coded request constants are summarized; dynamic parameters are not flattened.",
    ])


@dataclass(slots=True)
class J1939SignalDescription:
    name: str
    spn: int | None
    start: int
    length: int
    byte_order: str
    is_signed: bool
    scale: float
    offset: float
    minimum: float | None
    maximum: float | None
    unit: str | None


@dataclass(slots=True)
class J1939MessageDescription:
    name: str
    frame_id: int
    pgn: int
    priority: int
    source_address: int
    destination_address: int | None
    length: int
    signals: list[J1939SignalDescription]


@dataclass(slots=True)
class J1939Description:
    source: str
    messages: list[J1939MessageDescription]
    limitations: list[str] = field(default_factory=lambda: [
        "DBC signal metadata only; no SAE Digital Annex is bundled.",
        "The description does not automatically change generated PGNs, addressing or payloads.",
    ])


class UDSDescriptionParser:
    def load(self, file_path: str | Path, *, variant: str | None = None) -> UDSDescription:
        path = Path(file_path)
        if path.suffix.lower() not in {".odx", ".odx-d", ".pdx"}:
            raise ValueError(f"{path}: expected an .odx, .odx-d or .pdx description")
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            import odxtools
            from odxtools.parameters.codedconstparameter import CodedConstParameter
        except ImportError as exc:
            raise ImportError("ODX/PDX loading requires `pip install -e .[descriptions]`") from exc

        # Never extract PDX members onto disk; limit package expansion before parsing.
        if path.suffix.lower() == ".pdx":
            with zipfile.ZipFile(path) as archive:
                if sum(member.file_size for member in archive.infolist()) > 128 * 1024 * 1024:
                    raise ValueError(f"{path}: PDX uncompressed size exceeds 128 MiB")
        database = odxtools.load_file(path)
        layers = list(database.ecus) or list(database.diag_layers)
        names = [layer.short_name for layer in layers]
        if not names:
            raise ValueError(f"{path}: no diagnostic layers found")
        if variant is None and len(layers) != 1:
            raise ValueError(f"{path}: select odx_variant / --odx-variant from {', '.join(names)}")
        matches = [layer for layer in layers if variant is None or layer.short_name == variant]
        if len(matches) != 1:
            raise ValueError(f"{path}: unknown or ambiguous variant {variant!r}; available: {', '.join(names)}")
        layer = matches[0]
        services = []
        for service in layer.services:
            constants: dict[str, int | str] = {}
            service_id = None
            for parameter in service.request.parameters:
                if not isinstance(parameter, CodedConstParameter):
                    continue
                value = parameter.coded_value
                if isinstance(value, (int, str)):
                    constants[parameter.short_name] = value
                if (
                    parameter.byte_position == 0
                    and parameter.bit_position in (None, 0)
                    and parameter.diag_coded_type.get_static_bit_length() == 8
                    and isinstance(value, int)
                    and not isinstance(value, bool)
                    and 0 <= value <= 255
                ):
                    service_id = value
            services.append(UDSServiceDescription(
                name=service.short_name,
                request_name=service.request.short_name,
                service_id=service_id,
                constants=constants,
            ))
        if not services:
            raise ValueError(f"{path}: selected layer {layer.short_name!r} contains no diagnostic services")
        return UDSDescription(str(path), layer.short_name, names, services)


class J1939DescriptionParser:
    def load(self, file_path: str | Path) -> J1939Description:
        path = Path(file_path)
        if path.suffix.lower() != ".dbc":
            raise ValueError(f"{path}: expected a .dbc description")
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            import cantools
        except ImportError as exc:
            raise ImportError("DBC loading requires `pip install -e .[descriptions]`") from exc
        database = cantools.database.load_file(path, database_format="dbc", strict=True)
        messages = []
        skipped = []
        for message in database.messages:
            if not message.is_extended_frame:
                skipped.append(message.name)
                continue
            identifier = message.frame_id
            pf = (identifier >> 16) & 0xFF
            ps = (identifier >> 8) & 0xFF
            pgn = (identifier >> 8) & 0x3FFFF
            if pf < 240:
                pgn &= 0x3FF00
            signals = [
                J1939SignalDescription(
                    name=signal.name, spn=signal.spn, start=signal.start, length=signal.length,
                    byte_order=signal.byte_order, is_signed=signal.is_signed,
                    scale=signal.scale, offset=signal.offset, minimum=signal.minimum,
                    maximum=signal.maximum, unit=signal.unit,
                )
                for signal in message.signals
            ]
            messages.append(J1939MessageDescription(
                name=message.name, frame_id=identifier, pgn=pgn,
                priority=(identifier >> 26) & 7, source_address=identifier & 255,
                destination_address=ps if pf < 240 else None, length=message.length, signals=signals,
            ))
        if not messages:
            raise ValueError(f"{path}: no extended CAN messages available for J1939 interpretation")
        description = J1939Description(str(path), messages)
        description.limitations.append(
            "Extended messages are interpreted using J1939 identifier rules; an extended ID alone does not establish J1939."
        )
        if skipped:
            description.limitations.append(f"Skipped non-J1939 standard-ID messages: {', '.join(skipped)}")
        return description


def load_uds_description(odx: Path | None, pdx: Path | None, variant: str | None = None) -> UDSDescription | None:
    if odx is not None and pdx is not None:
        raise ValueError("specify only one of odx and pdx")
    path = odx or pdx
    if path is None:
        if variant is not None:
            raise ValueError("odx_variant requires an odx or pdx file")
        return None
    description = UDSDescriptionParser().load(path, variant=variant)
    print(f"[uds] loaded description variant={description.variant} services={len(description.services)} (metadata only)")
    return description
