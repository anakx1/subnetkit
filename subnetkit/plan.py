"""Persistent subnet plans for subnetkit.

Plans are plain JSON documents::

    {
      "parent": "10.0.0.0/16",
      "subnets": [
        {"name": "LAN", "cidr": "10.0.0.0/24", "vlan": 10, "notes": ""}
      ]
    }

Only the Python standard library is used.  The file helpers are intentionally
thin; the in-memory helpers (``validate_plan``, ``free_space``,
``add_subnet``) make the web API easy to use without touching the filesystem.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import core

InputError = core.InputError
EXPORT_FORMATS = ("csv", "json", "cisco", "iproute2", "terraform")
MAX_OVERLAP_ERRORS = 1000


# ---------------------------------------------------------------------------
# JSON file handling
# ---------------------------------------------------------------------------

def _coerce_vlan(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return value
    return value


def _normalise_entry(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise InputError(f"Subnet #{index} must be a JSON object.")
    name = item.get("name", "")
    cidr = item.get("cidr", "")
    notes = item.get("notes", "")
    if name is None:
        name = ""
    elif not isinstance(name, str):
        name = str(name)
    if cidr is None:
        cidr = ""
    elif not isinstance(cidr, str):
        cidr = str(cidr)
    if notes is None:
        notes = ""
    elif not isinstance(notes, str):
        notes = str(notes)
    return {
        "name": name,
        "cidr": cidr,
        "vlan": _coerce_vlan(item.get("vlan")),
        "notes": notes,
    }


def _as_plan(plan: Any) -> dict[str, Any]:
    """Accept either a plan dictionary or a filesystem path."""
    if isinstance(plan, (str, Path)):
        return load_plan(plan)
    if not isinstance(plan, dict):
        raise InputError("A plan must be a JSON object.")
    return plan


def _normalise_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise InputError("A plan must be a JSON object.")
    parent = plan.get("parent")
    if not isinstance(parent, str) or not parent.strip():
        raise InputError("Plan is missing a parent network.")
    subnets = plan.get("subnets", [])
    if subnets is None:
        subnets = []
    if not isinstance(subnets, list):
        raise InputError("Plan 'subnets' must be a JSON array.")
    return {
        "parent": parent.strip(),
        "subnets": [
            _normalise_entry(item, index)
            for index, item in enumerate(subnets, 1)
        ],
    }


def load_plan(path: str | Path) -> dict[str, Any]:
    """Load and structurally normalise a plan file."""
    file_path = Path(path)
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"Could not read plan file '{file_path}': {exc}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"Plan file '{file_path}' is not valid JSON: "
            f"{exc.msg} (line {exc.lineno}, column {exc.colno})."
        ) from exc
    return _normalise_plan(value)


def save_plan(path: str | Path, plan: dict[str, Any]) -> dict[str, Any]:
    """Write a plan as pretty, newline-terminated JSON."""
    file_path = Path(path)
    normalised = _normalise_plan(plan)
    try:
        file_path.write_text(
            json.dumps(normalised, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        raise InputError(f"Could not write plan file '{file_path}': {exc}") from exc
    return normalised


def init_plan(
    path: str | Path,
    parent: str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Create a new plan file.  Existing files are protected unless forced."""
    file_path = Path(path)
    if file_path.exists() and not force:
        raise InputError(
            f"Plan file '{file_path}' already exists; use --force to overwrite it."
        )
    plan = new_plan(parent)
    save_plan(file_path, plan)
    return plan


def new_plan(parent: str) -> dict[str, Any]:
    _, network, _ = core.parse_network(parent)
    return {"parent": network.with_prefixlen, "subnets": []}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _parent_network(plan: dict[str, Any]) -> ipaddress._BaseNetwork:
    parent = plan.get("parent", "")
    try:
        _, network, _ = core.parse_network(str(parent))
    except InputError as exc:
        raise InputError(f"Invalid plan parent: {exc}") from exc
    return network


def _entry_network(entry: dict[str, Any]) -> ipaddress._BaseNetwork:
    try:
        _, network, _ = core.parse_network(str(entry.get("cidr", "")))
    except InputError as exc:
        raise InputError(
            f"Invalid CIDR for subnet '{entry.get('name') or 'unnamed'}': {exc}"
        ) from exc
    return network


def validate_plan(plan: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Check parent containment, overlaps, duplicate names, and duplicate VLANs."""
    normalised = _normalise_plan(_as_plan(plan))
    errors: list[dict[str, Any]] = []
    parent: ipaddress._BaseNetwork | None = None
    try:
        parent = _parent_network(normalised)
    except InputError as exc:
        errors.append(
            {
                "code": "invalid-parent",
                "message": str(exc),
                "index": 0,
                "name": "",
                "cidr": normalised["parent"],
            }
        )

    names: dict[str, int] = {}
    vlans: dict[int, int] = {}
    parsed: list[tuple[int, str, str, ipaddress._BaseNetwork]] = []

    for index, entry in enumerate(normalised["subnets"], 1):
        name = entry["name"]
        cidr = entry["cidr"]
        vlan = entry["vlan"]

        if not name.strip():
            errors.append(
                {
                    "code": "invalid-name",
                    "message": f"Subnet #{index} has no name.",
                    "index": index,
                    "name": name,
                    "cidr": cidr,
                }
            )
        elif name in names:
            errors.append(
                {
                    "code": "duplicate-name",
                    "message": (
                        f"Duplicate subnet name '{name}' "
                        f"(#{names[name]} and #{index})."
                    ),
                    "index": index,
                    "other_index": names[name],
                    "name": name,
                    "cidr": cidr,
                }
            )
        else:
            names[name] = index

        if vlan is not None:
            try:
                if isinstance(vlan, float) and not vlan.is_integer():
                    raise ValueError
                vlan_number = int(vlan)
            except (TypeError, ValueError):
                errors.append(
                    {
                        "code": "invalid-vlan",
                        "message": (
                            f"Subnet '{name or f'#{index}'}' has an invalid "
                            f"VLAN '{vlan}'."
                        ),
                        "index": index,
                        "name": name,
                        "cidr": cidr,
                    }
                )
            else:
                if vlan_number in vlans:
                    errors.append(
                        {
                            "code": "duplicate-vlan",
                            "message": (
                                f"Duplicate VLAN {vlan_number} "
                                f"(#{vlans[vlan_number]} and #{index})."
                            ),
                            "index": index,
                            "other_index": vlans[vlan_number],
                            "name": name,
                            "cidr": cidr,
                            "vlan": vlan_number,
                        }
                    )
                else:
                    vlans[vlan_number] = index

        try:
            network = _entry_network(entry)
        except InputError as exc:
            errors.append(
                {
                    "code": "invalid-cidr",
                    "message": str(exc),
                    "index": index,
                    "name": name,
                    "cidr": cidr,
                }
            )
            continue

        if parent is not None:
            if network.version != parent.version:
                errors.append(
                    {
                        "code": "outside-parent",
                        "message": (
                            f"Subnet '{name or f'#{index}'}' ({cidr}) is IPv"
                            f"{network.version}, but the parent is IPv"
                            f"{parent.version}."
                        ),
                        "index": index,
                        "name": name,
                        "cidr": cidr,
                    }
                )
            elif not network.subnet_of(parent):
                errors.append(
                    {
                        "code": "outside-parent",
                        "message": (
                            f"Subnet '{name or f'#{index}'}' ({cidr}) is "
                            f"outside the parent {parent.with_prefixlen}."
                        ),
                        "index": index,
                        "name": name,
                        "cidr": cidr,
                    }
                )
        parsed.append((index, name, cidr, network))

    # Sort by start address so non-overlapping plans are linear-ish rather than
    # quadratic.  A pair can only overlap while the later start is not past the
    # earlier end; once it is, every later network starts even further away.
    parsed.sort(
        key=lambda item: (
            int(item[3].network_address),
            int(item[3].broadcast_address),
        )
    )
    overlap_errors = 0
    overlap_limit_reached = False
    for left_index, (index_a, name_a, cidr_a, network_a) in enumerate(parsed):
        if overlap_limit_reached:
            break
        end_a = int(network_a.broadcast_address)
        for right_index in range(left_index + 1, len(parsed)):
            index_b, name_b, cidr_b, network_b = parsed[right_index]
            if int(network_b.network_address) > end_a:
                break
            if not network_a.overlaps(network_b):
                continue
            if overlap_errors >= MAX_OVERLAP_ERRORS:
                errors.append(
                    {
                        "code": "too-many-overlaps",
                        "message": (
                            "Too many overlapping subnet pairs; only the "
                            f"first {MAX_OVERLAP_ERRORS:,} overlaps are shown."
                        ),
                        "index": index_a,
                        "name": name_a,
                        "cidr": cidr_a,
                    }
                )
                overlap_limit_reached = True
                break
            overlap_errors += 1
            errors.append(
                {
                    "code": "overlap",
                    "message": (
                        f"Subnet '{name_a or f'#{index_a}'}' ({cidr_a}) "
                        f"overlaps '{name_b or f'#{index_b}'}' ({cidr_b})."
                    ),
                    "index": index_a,
                    "other_index": index_b,
                    "indexes": [index_a, index_b],
                    "names": [name_a, name_b],
                    "name": name_a,
                    "cidr": cidr_a,
                }
            )

    for error in errors:
        error.setdefault("type", error["code"])
        error.setdefault("kind", error["code"])
    messages = [error["message"] for error in errors]
    return {
        "kind": "plan-validate",
        "valid": not errors,
        "ok": not errors,
        "parent": parent.with_prefixlen if parent is not None else normalised["parent"],
        "version": parent.version if parent is not None else None,
        "subnet_count": len(normalised["subnets"]),
        "errors": errors,
        "error_messages": messages,
        "messages": messages,
    }


def validate_file(path: str | Path) -> dict[str, Any]:
    return validate_plan(load_plan(path))


# ---------------------------------------------------------------------------
# Free space and allocation
# ---------------------------------------------------------------------------

def free_space(plan: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Return the parent's free space after subtracting the planned subnets."""
    normalised = _normalise_plan(_as_plan(plan))
    parent = _parent_network(normalised)
    allocated: list[str] = []
    notes: list[str] = []
    for entry in normalised["subnets"]:
        try:
            _, network, _ = core.parse_network(entry["cidr"])
        except InputError as exc:
            notes.append(
                f"Ignored subnet '{entry['name'] or 'unnamed'}': {exc}"
            )
            continue
        allocated.append(network.with_prefixlen)

    report = core.exclude(parent.with_prefixlen, allocated)
    free = report["cidr_list"]
    allocated_addresses = parent.num_addresses - report["total_addresses"]
    return {
        "kind": "plan-free",
        "parent": parent.with_prefixlen,
        "version": parent.version,
        "subnet_count": len(normalised["subnets"]),
        "free_blocks": free,
        "cidr_list": free,
        "free": free,
        "remaining": free,
        "free_count": len(free),
        "free_addresses": report["total_addresses"],
        "free_display": report["total_display"],
        "total_addresses": report["total_addresses"],
        "total_display": report["total_display"],
        "allocated_addresses": allocated_addresses,
        "allocated_display": f"{allocated_addresses:,}",
        "notes": notes + report["notes"],
    }


def free_blocks(plan: dict[str, Any]) -> list[str]:
    return list(free_space(plan)["free_blocks"])


def free_file(path: str | Path) -> dict[str, Any]:
    return free_space(load_plan(path))


def _no_space_error(
    name: str,
    hosts: int,
    needed: int,
    parent: ipaddress._BaseNetwork,
    free: Iterable[ipaddress._BaseNetwork],
    version: int,
) -> InputError:
    required = 1 << (core.MAX_PREFIX[version] - needed)
    candidates = list(free)
    if not candidates:
        return InputError(
            f"Not enough space for '{name}': {hosts:,} hosts need "
            f"{required:,} addresses (/{needed}), but no free blocks remain "
            f"in {parent.with_prefixlen}."
        )
    largest = max(candidates, key=lambda network: network.num_addresses)
    shortfall = max(0, required - largest.num_addresses)
    return InputError(
        f"Not enough space for '{name}': {hosts:,} hosts need "
        f"{required:,} addresses (/{needed}), but the largest free block is "
        f"{largest.with_prefixlen} with {largest.num_addresses:,} addresses "
        f"— short {shortfall:,} addresses."
    )


def add_subnet(
    plan: dict[str, Any] | str | Path,
    name: str,
    hosts: int,
    *,
    vlan: int | float | str | None = None,
    classic: bool = False,
    gateway: bool = False,
) -> dict[str, Any]:
    """Add one subnet using best-fit allocation from the current free space.

    A plan dictionary is mutated in place and the new entry is returned.  A
    filesystem path is loaded, updated, and saved instead.
    """
    if isinstance(plan, (str, Path)):
        return add_to_file(
            plan,
            name,
            hosts,
            vlan=vlan,
            classic=classic,
            gateway=gateway,
        )
    clean_name = str(name).strip()
    if not clean_name:
        raise InputError("Subnet name must not be empty.")
    try:
        host_count = int(hosts)
    except (TypeError, ValueError) as exc:
        raise InputError("Host count must be a whole number.") from exc
    if host_count < 1:
        raise InputError("Host count must be at least 1.")

    vlan_value: int | None
    if vlan is None:
        vlan_value = None
    else:
        try:
            if isinstance(vlan, float) and not vlan.is_integer():
                raise ValueError
            vlan_value = int(vlan)
        except (TypeError, ValueError) as exc:
            raise InputError("VLAN must be a whole number.") from exc

    report = validate_plan(plan)
    if not report["valid"]:
        messages = "; ".join(
            error["message"] for error in report["errors"][:3]
        )
        raise InputError(f"Plan has validation errors: {messages}")

    normalised = _normalise_plan(plan)
    if any(entry["name"] == clean_name for entry in normalised["subnets"]):
        raise InputError(f"Duplicate subnet name '{clean_name}'.")
    if vlan_value is not None and any(
        entry["vlan"] == vlan_value for entry in normalised["subnets"]
    ):
        raise InputError(f"Duplicate VLAN {vlan_value}.")

    parent = _parent_network(normalised)
    needed = core.prefix_for_hosts(
        host_count,
        parent.version,
        classic=classic,
        gateway=gateway,
    )
    free_report = free_space(normalised)
    free = [ipaddress.ip_network(cidr) for cidr in free_report["free_blocks"]]
    candidates = [network for network in free if network.prefixlen <= needed]
    if not candidates:
        raise _no_space_error(
            clean_name,
            host_count,
            needed,
            parent,
            free,
            parent.version,
        )

    chosen = max(candidates, key=lambda network: network.prefixlen)
    allocated = ipaddress.ip_network(
        f"{chosen.network_address}/{needed}", strict=False
    )
    entry = {
        "name": clean_name,
        "cidr": allocated.with_prefixlen,
        "vlan": vlan_value,
        "notes": "",
    }
    plan.setdefault("subnets", []).append(entry)
    return entry


def add_to_file(
    path: str | Path,
    name: str,
    hosts: int,
    *,
    vlan: int | float | str | None = None,
    classic: bool = False,
    gateway: bool = False,
) -> dict[str, Any]:
    plan = load_plan(path)
    entry = add_subnet(
        plan,
        name,
        hosts,
        vlan=vlan,
        classic=classic,
        gateway=gateway,
    )
    save_plan(path, plan)
    return entry


# ---------------------------------------------------------------------------
# Show / summaries
# ---------------------------------------------------------------------------

def show_plan(plan: dict[str, Any] | str | Path) -> dict[str, Any]:
    normalised = _normalise_plan(_as_plan(plan))
    validation = validate_plan(normalised)
    try:
        parent = _parent_network(normalised)
        free = free_space(normalised)
        parent_text = parent.with_prefixlen
        version = parent.version
    except InputError:
        free = None
        parent_text = normalised["parent"]
        version = None
    result: dict[str, Any] = {
        "kind": "plan",
        "parent": parent_text,
        "version": version,
        "subnets": normalised["subnets"],
        "plan": normalised,
        "subnet_count": len(normalised["subnets"]),
        "validation": validation,
    }
    if free is not None:
        result["free"] = free
        result["free_blocks"] = free["free_blocks"]
        result["free_addresses"] = free["free_addresses"]
        result["free_display"] = free["free_display"]
    return result


def show_file(path: str | Path) -> dict[str, Any]:
    return show_plan(load_plan(path))


# ---------------------------------------------------------------------------
# Export formats
# ---------------------------------------------------------------------------

def _first_host(network: ipaddress._BaseNetwork) -> ipaddress._BaseAddress:
    if network.version == core.V4 and network.prefixlen >= 31:
        return network.network_address
    if network.version == core.V6 and network.prefixlen >= 127:
        return network.network_address
    return network.network_address + 1


def _interface_name(name: str, vlan: Any = None) -> str:
    if vlan is not None:
        return f"vlan{vlan}"
    cleaned = "".join(
        character.lower()
        if character.isalnum()
        else "-"
        for character in name.strip()
    ).strip("-")
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    if not cleaned:
        cleaned = "subnet"
    if cleaned[0].isdigit():
        cleaned = f"subnet-{cleaned}"
    return cleaned


def _export_csv(plan: dict[str, Any]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["name", "cidr", "vlan", "notes"])
    for entry in plan["subnets"]:
        writer.writerow(
            [
                entry["name"],
                entry["cidr"],
                "" if entry["vlan"] is None else entry["vlan"],
                entry["notes"],
            ]
        )
    return output.getvalue()


def _export_json(plan: dict[str, Any]) -> str:
    return json.dumps(plan, indent=2) + "\n"


def _export_cisco(plan: dict[str, Any]) -> str:
    lines = ["! subnetkit plan", f"! parent {plan['parent']}"]
    for entry in plan["subnets"]:
        name = entry["name"] or "unnamed"
        cidr = entry["cidr"]
        vlan = entry["vlan"]
        notes = entry["notes"]
        suffix = ""
        if vlan is not None:
            suffix += f" vlan {vlan}"
        if notes:
            suffix += f" notes: {notes}"
        lines.append(f"! {name} {cidr}{suffix}")
        try:
            _, network, _ = core.parse_network(cidr)
        except InputError:
            lines.append("! invalid CIDR; no interface address generated")
            continue
        if vlan is not None:
            lines.append(f"vlan {vlan}")
            lines.append(f" name {name}")
            interface = f"Vlan{vlan}"
        else:
            interface = _interface_name(name)
        lines.append(f"interface {interface}")
        lines.append(f" description {name}")
        if notes:
            lines.append(f" ! {notes}")
        if network.version == core.V4:
            lines.append(
                f" ip address {_first_host(network)} {network.netmask}"
            )
        else:
            lines.append(
                f" ipv6 address {_first_host(network)}/{network.prefixlen}"
            )
        lines.append("!")
    return "\n".join(lines) + "\n"


def _export_iproute2(plan: dict[str, Any]) -> str:
    lines = ["# subnetkit plan", f"# parent {plan['parent']}"]
    for entry in plan["subnets"]:
        name = entry["name"] or "unnamed"
        cidr = entry["cidr"]
        vlan = entry["vlan"]
        notes = entry["notes"]
        lines.append(
            f"# {name} {cidr}" + (f" — {notes}" if notes else "")
        )
        try:
            _, network, _ = core.parse_network(cidr)
        except InputError:
            lines.append("# invalid CIDR; no route generated")
            continue
        command = "ip -6 route add" if network.version == core.V6 else "ip route add"
        device = _interface_name(name, vlan)
        lines.append(f"{command} {network.with_prefixlen} dev {device}")
    return "\n".join(lines) + "\n"


def _export_terraform(plan: dict[str, Any]) -> str:
    lines = [
        "# subnetkit plan",
        f"# parent {plan['parent']}",
        "locals {",
        "  subnetkit_subnets = {",
    ]
    for entry in plan["subnets"]:
        key = json.dumps(entry["name"] or "unnamed")
        lines.append(f"    {key} = {{")
        lines.append(f"      cidr_block = {json.dumps(entry['cidr'])}")
        lines.append(
            "      vlan = "
            + ("null" if entry["vlan"] is None else str(entry["vlan"]))
        )
        lines.append(f"      notes = {json.dumps(entry['notes'])}")
        lines.append("    }")
    lines.extend(["  }", "}"])
    return "\n".join(lines) + "\n"


def export_plan(plan: dict[str, Any] | str | Path, fmt: str) -> str:
    """Export a plan as csv, json, cisco, iproute2, or terraform."""
    normalised = _normalise_plan(_as_plan(plan))
    format_name = str(fmt).strip().lower()
    exporters = {
        "csv": _export_csv,
        "json": _export_json,
        "cisco": _export_cisco,
        "iproute2": _export_iproute2,
        "terraform": _export_terraform,
    }
    try:
        exporter = exporters[format_name]
    except KeyError as exc:
        raise InputError(
            "Unknown export format "
            f"'{fmt}'; choose from {', '.join(EXPORT_FORMATS)}."
        ) from exc
    return exporter(normalised)


def export_file(path: str | Path, fmt: str) -> str:
    return export_plan(load_plan(path), fmt)


# Convenient aliases for callers that prefer short names.
load = load_plan
save = save_plan
create = init_plan
validate = validate_plan
free = free_space
show = show_plan
export = export_plan
add = add_subnet
init = init_plan
