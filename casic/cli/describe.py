from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from casic.core.parser import J1939DescriptionParser, UDSDescriptionParser


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="casic-describe", description="Inspect ODX/PDX or J1939 DBC metadata without opening a CAN interface.",
    )
    parser.add_argument("file", type=Path)
    parser.add_argument("--variant", help="ODX ECU variant short name")
    args = parser.parse_args(argv)
    try:
        if args.file.suffix.lower() == ".dbc":
            if args.variant is not None:
                parser.error("--variant applies only to ODX/PDX")
            description = J1939DescriptionParser().load(args.file)
        else:
            description = UDSDescriptionParser().load(args.file, variant=args.variant)
        print(json.dumps(asdict(description), indent=2))
    except (OSError, ValueError, ImportError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
