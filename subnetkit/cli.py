"""Command-line interface for subnetkit."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Iterable, Sequence

from . import core

__version__ = "1.0.0"

_COLOR = False
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
RESET = "\033[0m"
BOLD = "1"
DIM = "2"
CYAN = "36"
GREEN = "32"
YELLOW = "33"
RED = "31"
MAGENTA = "35"


def _paint(text: Any, *codes: str) -> str:
    if not _COLOR:
        return str(text)
    return "".join(f"\033[{code}m" for code in codes) + str(text) + RESET


def _setup_color(stream=sys.stdout) -> None:
    global _COLOR
    _COLOR = bool(
        getattr(stream, "isatty", lambda: False)()
        and os.environ.get("TERM") != "dumb"
        and "NO_COLOR" not in os.environ
    )


def _title(text: str, meta: str = "") -> None:
    print()
    line = "  " + _paint(text, BOLD, CYAN)
    if meta:
        line += "  " + _paint(meta, DIM)
    print(line)
    print("  " + _paint("─" * 60, DIM))


def _kv(label: str, value: Any, width: int = 16) -> None:
    print(f"  {_paint(label.ljust(width), DIM)}{value}")


def _note_lines(notes: Iterable[str]) -> None:
    notes = list(notes)
    if not notes:
        return
    print()
    for note in notes:
        print("  " + _paint("· ", DIM) + _paint(note, DIM))


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]], right: Sequence[int] = ()) -> None:
    if not rows:
        return

    def visible_length(value: Any) -> int:
        return len(_ANSI_RE.sub("", str(value)))

    def pad(value: Any, width: int, align_right: bool = False) -> str:
        text = str(value)
        gap = " " * max(0, width - visible_length(text))
        return gap + text if align_right else text + gap

    string_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(str(header)) for header in headers]
    for row in string_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], visible_length(cell))

    header_line = "  ".join(
        _paint(pad(header, widths[i]), DIM) for i, header in enumerate(headers)
    )
    print("  " + header_line)
    print("  " + _paint("  ".join("─" * width for width in widths), DIM))
    for row in string_rows:
        cells = [
            pad(cell, widths[i], i in right) for i, cell in enumerate(row)
        ]
        print("  " + "  ".join(cells).rstrip())


def _counts(usable: int, total: int, power: str | None = None) -> str:
    if power:
        return f"{usable:,} usable  ·  {power} total"
    return f"{usable:,} usable  ·  {total:,} total"


def _colored_bits(bits: str, prefix: int, group: int = 8) -> str:
    chunks = []
    for i, bit in enumerate(bits):
        if i and i % group == 0:
            chunks.append(" ")
        chunks.append(_paint(bit, CYAN) if i < prefix else _paint(bit, YELLOW))
    return "".join(chunks)


def _render_binary(label: str, bits: str, prefix: int, group: int = 8) -> None:
    print(f"  {_paint(label.ljust(16), DIM)}{_colored_bits(bits, prefix, group)}")


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_network(data: dict[str, Any]) -> None:
    _title(data["cidr"], f"IPv{data['version']} · {data['scope']}")
    if data.get("input_is_host"):
        _kv("Input", f"{data['address']}  {_paint('(no prefix)', DIM)}")
    _kv("Address", data["address"])
    _kv("Network", data["network_address"])
    _kv("Netmask", f"{data['netmask']}  {_paint('/' + str(data['prefix']), DIM)}")
    _kv("Wildcard", data["wildcard"])
    _kv("Host range", f"{data['first_host']} – {data['last_host']}")
    if data.get("broadcast"):
        _kv("Broadcast", data["broadcast"])
    _kv("Usable hosts", _counts(data["usable_hosts"], data["total_addresses"], data.get("total_power")))
    if data.get("class"):
        _kv("Class", data["class"])
    _kv("Scope", data["scope"])
    if data["version"] == 4:
        bits = data["binary"]["address_bits"]
        _render_binary("Address bits", bits, data["prefix"])
        print(
            "  "
            + " " * 16
            + _paint("network", CYAN)
            + _paint(" / ", DIM)
            + _paint("host", YELLOW)
        )
    _note_lines(data.get("notes", []))


def render_range(data: dict[str, Any]) -> None:
    _title(
        f"{data['start']}  –  {data['end']}",
        f"IPv{data['version']} · {data['total_display']} addresses",
    )
    _kv("Start", data["start"])
    _kv("End", data["end"])
    _kv("Addresses", f"{data['total_display']}" + (f"  {_paint(data['total_power'], DIM)}" if data.get("total_power") else ""))
    _kv("CIDR blocks", data["cidr_count"])
    _kv("Common prefix", data["common_prefix"])
    _kv("Scope", data["scope"])
    print()
    print("  " + _paint("CIDR blocks", DIM))
    for block in data["cidr_list"]:
        print(f"    {_paint(block, GREEN)}")
    _note_lines(data.get("notes", []))


def render_split(data: dict[str, Any]) -> None:
    _title(
        f"{data['parent']}  →  /{data['new_prefix']}",
        f"{data['generated_count']:,} subnet{'s' if data['generated_count'] != 1 else ''}",
    )
    subnets = data["subnets"]
    limit = len(subnets) if data.get("_all") else 256
    shown = subnets[:limit]

    if data["version"] == 4:
        rows = [
            [
                subnet["index"],
                subnet["cidr"],
                f"{subnet['first_host']} – {subnet['last_host']}",
                subnet["broadcast"],
                f"{subnet['usable_hosts']:,}",
            ]
            for subnet in shown
        ]
        _table(["#", "Network", "Host range", "Broadcast", "Usable"], rows, right=(0, 4))
    else:
        for subnet in shown:
            print(
                f"  {_paint(str(subnet['index']).rjust(3), DIM)}  "
                f"{_paint(subnet['cidr'], BOLD)}  "
                f"{_paint(subnet['total_power'] or subnet['total_display'], DIM)}"
            )
            print(f"       {subnet['first_host']} – {subnet['last_host']}")

    if len(subnets) > limit:
        print()
        print(
            "  "
            + _paint(
                f"… {len(subnets) - limit:,} more (use --all or --json to see everything)",
                DIM,
            )
        )
    _note_lines(data.get("notes", []))


def render_mask(data: dict[str, Any]) -> None:
    _title(f"/{data['prefix']}", f"IPv{data['version']} · mask calculator")
    _kv("Netmask", data["netmask"])
    if data["version"] == 6:
        _kv("Expanded", data["netmask_expanded"])
    _kv("Wildcard", data["wildcard"])
    _kv(
        "Addresses",
        data["total_display"] + (f"  {_paint(data['total_power'], DIM)}" if data.get("total_power") else ""),
    )
    _kv("Usable hosts", f"{data['usable_display']}")
    if data["version"] == 4:
        _render_binary("Netmask bits", data["binary"]["netmask_bits"], data["prefix"])
        print(
            "  "
            + " " * 16
            + _paint("1 = network", CYAN)
            + _paint(" · ", DIM)
            + _paint("0 = host", YELLOW)
        )
    _note_lines(data.get("notes", []))

    reference = data.get("quick_reference") or []
    if reference:
        print()
        print("  " + _paint("Common IPv4 masks", DIM))
        rows = [
            [
                f"/{row['prefix']}",
                row["netmask"],
                row["wildcard"],
                f"{row['usable_hosts']:,}" if row["prefix"] < 31 else ("2" if row["prefix"] == 31 else "1"),
            ]
            for row in reference
        ]
        _table(["Prefix", "Netmask", "Wildcard", "Hosts"], rows, right=(0, 3))


def render_vlsm(data: dict[str, Any]) -> None:
    _title(data["parent"], f"VLSM · {len(data['allocations'])} allocation{'s' if len(data['allocations']) != 1 else ''}")
    rows = []
    for allocation in data["allocations"]:
        rows.append(
            [
                allocation["name"],
                allocation["requested_hosts"],
                allocation["cidr"],
                f"{allocation['usable_hosts']:,}",
                allocation["waste"],
                f"{allocation['first_host']} – {allocation['last_host']}",
            ]
        )
    _table(["Name", "Needs", "Allocated", "Usable", "Waste", "Host range"], rows, right=(1, 3, 4))
    if data.get("free_blocks"):
        print()
        print("  " + _paint("Free space", DIM))
        for block in data["free_blocks"]:
            print(f"    {_paint(block, GREEN)}")
    _note_lines(data.get("notes", []))


_RELATION_STYLE = {
    "inside": GREEN,
    "subnet": GREEN,
    "outside": YELLOW,
    "supernet": YELLOW,
    "overlap": MAGENTA,
    "disjoint": DIM,
    "different-version": RED,
    "invalid": RED,
    "unsupported": RED,
}


def render_check(data: dict[str, Any]) -> None:
    _title(f"Check against {data['base']}", f"IPv{data['version']}")
    rows = []
    for result in data["results"]:
        style = _RELATION_STYLE.get(result["relation"], DIM)
        rows.append(
            [
                result["input"],
                _paint(result["relation"], style),
                result["note"],
            ]
        )
    _table(["Input", "Relation", "Detail"], rows)


def render_show(data: dict[str, Any]) -> None:
    if data["kind"] == "range":
        render_range(data)
    else:
        render_network(data)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def _parse_requirement(text: str, index: int) -> dict[str, Any]:
    raw = text.strip()
    if not raw:
        raise core.InputError("Empty VLSM requirement.")
    for separator in (":", "=", ","):
        if separator in raw:
            name, value = raw.rsplit(separator, 1)
            name = name.strip() or f"subnet-{index}"
            try:
                hosts = int(value.strip())
            except ValueError as exc:
                raise core.InputError(f"'{raw}' does not end in a host count.") from exc
            return {"name": name, "hosts": hosts}
    try:
        return {"name": f"subnet-{index}", "hosts": int(raw)}
    except ValueError as exc:
        raise core.InputError(
            f"'{raw}' is not a requirement. Use 'name:hosts' or a host count."
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subnetkit",
        description="IP and subnet calculator: CIDR, ranges, masks, splitting and VLSM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  subnetkit 192.168.1.10/24
  subnetkit 10.0.0.5 - 10.0.0.42
  subnetkit 2001:db8::1/64
  subnetkit split 192.168.1.0/24 -n 4
  subnetkit split 10.0.0.0/16 -p 24
  subnetkit summarize 192.168.1.5 192.168.1.42
  subnetkit mask 255.255.255.192
  subnetkit vlsm 192.168.1.0/24 LAN:100 WAN:2 Guest:20
  subnetkit check 10.0.0.0/8 10.1.2.3 192.168.0.0/16
  subnetkit web
""",
    )
    parser.add_argument("--version", action="version", version=f"subnetkit {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    show = subparsers.add_parser("show", help="inspect a CIDR, host, or range")
    show.add_argument("target", nargs="+", help="IP, CIDR block, or 'start - end' range")
    show.add_argument("--json", action="store_true", help="print JSON")

    split = subparsers.add_parser("split", help="split a network into subnets")
    split.add_argument("target", help="network in CIDR form")
    mode = split.add_mutually_exclusive_group(required=True)
    mode.add_argument("-n", "--count", type=int, help="number of subnets")
    mode.add_argument("-p", "--prefix", type=int, help="new prefix length")
    split.add_argument("--all", action="store_true", help="print every subnet")
    split.add_argument("--json", action="store_true", help="print JSON")

    summary = subparsers.add_parser("summarize", help="collapse an address range into CIDRs")
    summary.add_argument("start", help="start address, or 'start - end'")
    summary.add_argument("end", nargs="?", help="end address")
    summary.add_argument("--json", action="store_true", help="print JSON")

    mask = subparsers.add_parser("mask", help="convert prefix, netmask, and wildcard")
    mask.add_argument("mask", help="e.g. 255.255.255.192, /26, 26, or an IPv6 mask")
    mask.add_argument("--ipv6", action="store_true", help="treat a bare prefix as IPv6")
    mask.add_argument("--json", action="store_true", help="print JSON")

    vlsm = subparsers.add_parser("vlsm", help="allocate variable-size subnets")
    vlsm.add_argument("target", help="parent network in CIDR form")
    vlsm.add_argument(
        "requirements",
        nargs="+",
        help="requirements as name:hosts (or just a host count)",
    )
    vlsm.add_argument("--json", action="store_true", help="print JSON")

    check = subparsers.add_parser("check", help="check containment and overlap")
    check.add_argument("target", help="base network in CIDR form")
    check.add_argument("others", nargs="+", help="IPs or networks to test")
    check.add_argument("--json", action="store_true", help="print JSON")

    web = subparsers.add_parser("web", help="start the local web UI")
    web.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    web.add_argument("--port", type=int, default=8765, help="port (default 8765)")
    web.add_argument("--no-open", action="store_true", help="do not open a browser")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _setup_color()
    args_list = list(sys.argv[1:] if argv is None else argv)
    commands = {"show", "split", "summarize", "mask", "vlsm", "check", "web"}

    if not args_list:
        build_parser().print_help()
        return 0
    if args_list[0] == "--json":
        args_list = args_list[1:]
        if args_list and args_list[0] in commands:
            args_list.append("--json")
        else:
            args_list = ["show", "--json"] + args_list
    elif args_list[0].startswith("-") and args_list[0] not in ("-h", "--help", "--version"):
        args_list = ["show"] + args_list
    elif args_list[0] not in commands and args_list[0] not in ("-h", "--help", "--version"):
        args_list = ["show"] + args_list

    parser = build_parser()
    args = parser.parse_args(args_list)

    try:
        if args.command == "show":
            targets = args.target
            if len(targets) == 3 and targets[1].lower() in ("-", "–", "—", "to"):
                targets = [f"{targets[0]} - {targets[2]}"]
            results = [core.describe(target) for target in targets]
            if args.json:
                _print_json(results[0] if len(results) == 1 else results)
            else:
                for data in results:
                    render_show(data)
                print()
            return 0

        if args.command == "split":
            data = core.split_network(args.target, count=args.count, prefix=args.prefix)
            data["_all"] = args.all
            if args.json:
                data.pop("_all", None)
                _print_json(data)
            else:
                render_split(data)
                print()
            return 0

        if args.command == "summarize":
            if args.end is None:
                if not core.looks_like_range(args.start):
                    raise core.InputError(
                        "Provide an end address, or pass the range as 'start - end'."
                    )
                data = core.describe_range(args.start)
            else:
                data = core.summarize(args.start, args.end)
            if args.json:
                _print_json(data)
            else:
                render_range(data)
                print()
            return 0

        if args.command == "mask":
            data = core.mask_info(args.mask, 6 if args.ipv6 else 4)
            if args.json:
                _print_json(data)
            else:
                render_mask(data)
                print()
            return 0

        if args.command == "vlsm":
            requirements = [
                _parse_requirement(requirement, index + 1)
                for index, requirement in enumerate(args.requirements)
            ]
            data = core.vlsm(args.target, requirements)
            if args.json:
                _print_json(data)
            else:
                render_vlsm(data)
                print()
            return 0

        if args.command == "check":
            data = core.check_relations(args.target, args.others)
            if args.json:
                _print_json(data)
            else:
                render_check(data)
                print()
            return 0

        if args.command == "web":
            from .web import serve

            serve(host=args.host, port=args.port, open_browser=not args.no_open)
            return 0

        parser.print_help()
        return 0
    except core.InputError as exc:
        print(_paint("error:", BOLD, RED) + " " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
