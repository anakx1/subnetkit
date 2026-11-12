"""Core IP / subnet calculations for subnetkit.

Only the Python standard library is used.  Every public function returns
plain, JSON-serialisable dictionaries so the same logic powers the CLI and
the local web UI.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Sequence

V4 = 4
V6 = 6
BITS = {V4: 32, V6: 128}
MAX_PREFIX = {V4: 32, V6: 128}
MAX_SPLIT = 4096

_RANGE_RE = re.compile(
    r"^\s*([0-9a-fA-F:.]+)\s*(?:-|–|—|\bto\b)\s*([0-9a-fA-F:.]+)\s*$",
    re.IGNORECASE,
)

_SPECIAL_V4 = [
    ("0.0.0.0/8", "This network"),
    ("10.0.0.0/8", "Private"),
    ("100.64.0.0/10", "Shared (CGNAT)"),
    ("127.0.0.0/8", "Loopback"),
    ("169.254.0.0/16", "Link-local"),
    ("172.16.0.0/12", "Private"),
    ("192.0.0.0/24", "IETF protocol"),
    ("192.0.2.0/24", "Documentation"),
    ("192.88.99.0/24", "6to4 relay"),
    ("192.168.0.0/16", "Private"),
    ("198.18.0.0/15", "Benchmarking"),
    ("198.51.100.0/24", "Documentation"),
    ("203.0.113.0/24", "Documentation"),
    ("224.0.0.0/4", "Multicast"),
    ("255.255.255.255/32", "Limited broadcast"),
    ("240.0.0.0/4", "Reserved"),
]
_SPECIAL_V4_NETS = [(ipaddress.ip_network(cidr), label) for cidr, label in _SPECIAL_V4]

_SPECIAL_V6 = [
    ("::/128", "Unspecified"),
    ("::1/128", "Loopback"),
    ("::ffff:0:0/96", "IPv4-mapped"),
    ("64:ff9b::/96", "NAT64"),
    ("100::/64", "Discard"),
    ("2001:db8::/32", "Documentation"),
    ("2001:10::/28", "ORCHID"),
    ("2002::/16", "6to4"),
    ("fc00::/7", "Unique local"),
    ("fe80::/10", "Link-local"),
    ("ff00::/8", "Multicast"),
]
_SPECIAL_V6_NETS = [(ipaddress.ip_network(cidr), label) for cidr, label in _SPECIAL_V6]


class InputError(ValueError):
    """Raised for anything the user typed that cannot be parsed."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _pow2_label(n: int) -> str | None:
    if n > 0 and (n & (n - 1)) == 0:
        return f"2^{n.bit_length() - 1}"
    return None


def _default_prefix(ip: ipaddress._BaseAddress) -> int:
    if ip.version == V4:
        first = int(ip) >> 24
        if first < 128:
            return 8
        if first < 192:
            return 16
        if first < 224:
            return 24
        return 32
    return 64


def _normalise_input(text: str) -> str:
    text = (text or "").strip()
    if not text:
        raise InputError("Enter an IP address, CIDR block, mask, or range.")
    parts = text.split()
    if len(parts) == 2 and "/" not in parts[0]:
        # "192.168.1.10 255.255.255.0"
        text = f"{parts[0]}/{parts[1]}"
    elif len(parts) > 1:
        raise InputError("Too many values — use 'address/prefix' or 'address mask'.")
    return text


def looks_like_range(text: str) -> bool:
    return bool(_RANGE_RE.match((text or "").strip()))


def _parse_range(text: str) -> tuple[ipaddress._BaseAddress, ipaddress._BaseAddress]:
    match = _RANGE_RE.match((text or "").strip())
    if not match:
        raise InputError("That does not look like an IP range.")
    try:
        start = ipaddress.ip_address(match.group(1))
    except ValueError as exc:
        raise InputError(f"Invalid range start: {match.group(1)} ({exc})") from exc
    try:
        end = ipaddress.ip_address(match.group(2))
    except ValueError as exc:
        raise InputError(f"Invalid range end: {match.group(2)} ({exc})") from exc
    if start.version != end.version:
        raise InputError("Range start and end must be the same IP version.")
    return start, end


def parse_network(text: str) -> tuple[ipaddress._BaseAddress, ipaddress._BaseNetwork, bool]:
    """Parse a CIDR/host input, returning (address, network, assumed_prefix)."""
    text = _normalise_input(text)
    assumed = False
    if "/" in text:
        addr_part = text.rsplit("/", 1)[0]
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise InputError(str(exc).replace("has host bits set", "has host bits set")) from exc
        try:
            address = ipaddress.ip_address(addr_part)
        except ValueError:
            address = network.network_address
    else:
        try:
            address = ipaddress.ip_address(text)
        except ValueError as exc:
            raise InputError(f"'{text}' is not a valid IP address or CIDR block.") from exc
        prefix = _default_prefix(address)
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        assumed = True
    if address.version != network.version:
        raise InputError("Address and prefix are different IP versions.")
    return address, network, assumed


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _ipv4_class(ip: ipaddress.IPv4Address) -> str:
    first = int(ip) >> 24
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D"
    return "E"


def _scope(network: ipaddress._BaseNetwork) -> str:
    if network.prefixlen == 0:
        return "Global"
    address = network.network_address
    if network.version == V4:
        for special, label in _SPECIAL_V4_NETS:
            if address in special:
                return label
        return "Public"
    for special, label in _SPECIAL_V6_NETS:
        if address in special:
            return label
    return "Global unicast"


def _flags(network: ipaddress._BaseNetwork) -> list[str]:
    pairs = [
        ("is_private", "Private"),
        ("is_global", "Global"),
        ("is_loopback", "Loopback"),
        ("is_link_local", "Link-local"),
        ("is_multicast", "Multicast"),
        ("is_reserved", "Reserved"),
        ("is_unspecified", "Unspecified"),
    ]
    return [label for attr, label in pairs if getattr(network, attr, False)]


def _host_bounds(network: ipaddress._BaseNetwork):
    total = network.num_addresses
    if network.version == V4:
        if network.prefixlen >= 31:
            return network.network_address, network.broadcast_address, total
        return network.network_address + 1, network.broadcast_address - 1, max(0, total - 2)
    return network.network_address, network.broadcast_address, total


def _bits(value: int, width: int) -> str:
    return format(value, f"0{width}b")


def _binary_info(address, network, netmask) -> dict[str, Any]:
    width = BITS[network.version]
    return {
        "prefix": network.prefixlen,
        "address_bits": _bits(int(address), width),
        "network_bits": _bits(int(network.network_address), width),
        "netmask_bits": _bits(int(netmask), width),
        "width": width,
    }


def _network_payload(
    address: ipaddress._BaseAddress,
    network: ipaddress._BaseNetwork,
    assumed: bool,
    raw: str,
) -> dict[str, Any]:
    first, last, usable = _host_bounds(network)
    version = network.version
    total = network.num_addresses
    is_v4 = version == V4

    notes: list[str] = []
    if assumed:
        kind = "classful default" if is_v4 else "standard subnet size"
        notes.append(f"No prefix supplied, so /{network.prefixlen} was assumed ({kind}).")
    if address != network.network_address:
        notes.append(
            f"Host bits were cleared: {address} is inside {network.with_prefixlen}."
        )
    if is_v4 and network.prefixlen == 31 and not assumed:
        notes.append("Point-to-point /31: both addresses are usable (RFC 3021).")
    if is_v4 and network.prefixlen == 32 and not assumed:
        notes.append("Single-host /32 route: one usable address.")
    if not is_v4 and network.prefixlen == 64:
        notes.append("IPv6 /64 is the standard LAN size — 2^64 addresses.")
    if not is_v4 and network.prefixlen == 127:
        notes.append("IPv6 /127 is commonly used for point-to-point links (RFC 6164).")
    if not is_v4 and network.prefixlen == 128:
        notes.append("Single-host /128 route.")

    payload: dict[str, Any] = {
        "kind": "network",
        "input": raw,
        "version": version,
        "cidr": network.with_prefixlen,
        "prefix": network.prefixlen,
        "netmask": str(network.netmask),
        "netmask_expanded": (str(network.netmask.exploded) if not is_v4 else str(network.netmask)),
        "wildcard": str(network.hostmask),
        "network_address": str(network.network_address),
        "address": str(address),
        "input_is_host": assumed,
        "host_offset": int(address) - int(network.network_address),
        "first_host": str(first),
        "last_host": str(last),
        "broadcast": str(network.broadcast_address) if is_v4 else None,
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "usable_hosts": usable,
        "usable_display": f"{usable:,}",
        "class": _ipv4_class(address) if is_v4 else None,
        "scope": _scope(network),
        "flags": _flags(network),
        "is_private": network.is_private,
        "is_global": network.is_global,
        "binary": _binary_info(address, network, network.netmask),
        "notes": notes,
    }
    return payload


# ---------------------------------------------------------------------------
# Describe: CIDR / host / range
# ---------------------------------------------------------------------------

def describe_network(text: str) -> dict[str, Any]:
    address, network, assumed = parse_network(text)
    return _network_payload(address, network, assumed, text.strip())


def describe_range(text: str) -> dict[str, Any]:
    start, end = _parse_range(text)
    notes: list[str] = []
    if int(start) > int(end):
        start, end = end, start
        notes.append("Start was after end, so the range was reversed.")

    count = int(end) - int(start) + 1
    blocks = list(ipaddress.summarize_address_range(start, end))
    common_bits = BITS[start.version] - (int(start) ^ int(end)).bit_length()
    common = ipaddress.ip_network(f"{start}/{common_bits}", strict=False)

    notes.append(
        f"Summarised into {len(blocks)} CIDR block{'s' if len(blocks) != 1 else ''}."
    )
    if len(blocks) == 1:
        notes.append("The range is exactly one CIDR block.")

    return {
        "kind": "range",
        "input": text.strip(),
        "version": start.version,
        "start": str(start),
        "end": str(end),
        "total_addresses": count,
        "total_display": f"{count:,}",
        "total_power": _pow2_label(count),
        "cidr_count": len(blocks),
        "cidr_list": [block.with_prefixlen for block in blocks],
        "common_prefix": common.with_prefixlen,
        "scope": _scope(common),
        "notes": notes,
    }


def describe(text: str) -> dict[str, Any]:
    """Describe a CIDR, host address, or IP range."""
    if looks_like_range(text):
        return describe_range(text)
    return describe_network(text)


def summarize(start: str, end: str | None = None) -> dict[str, Any]:
    """Summarise an address range into the smallest set of CIDR blocks."""
    if end is None:
        return describe_range(start)
    return describe_range(f"{start} - {end}")


# ---------------------------------------------------------------------------
# Masks
# ---------------------------------------------------------------------------

def _prefix_from_mask_bits(mask_int: int, width: int, original: str) -> int:
    binary = _bits(mask_int, width)
    if "01" in binary:
        raise InputError(
            f"'{original}' is not a contiguous netmask: {binary} has a 0 before a 1."
        )
    return binary.count("1")


def _is_contiguous_mask(mask_int: int, width: int) -> bool:
    return "01" not in _bits(mask_int, width)


def _mask_input_kind(mask: str) -> str:
    text = (mask or "").strip().replace(" ", "")
    if text.startswith("/") or text.isdigit():
        return "prefix"
    if ":" in text:
        return "netmask"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if _is_contiguous_mask(int(address), 32):
        return "netmask"
    inverse = ((1 << 32) - 1) ^ int(address)
    if int(address) != 0 and _is_contiguous_mask(inverse, 32):
        return "wildcard"
    return "invalid"


def parse_mask(mask: str, version: int = V4) -> tuple[int, int]:
    """Return (prefix, ip_version) for /24, 24, 255.255.255.0 or an IPv6 mask."""
    text = (mask or "").strip().replace(" ", "")
    if not text:
        raise InputError("Enter a mask, such as 255.255.255.0, /24, or 24.")
    if text.startswith("/"):
        text = text[1:]

    if text.isdigit():
        prefix = int(text)
        try:
            version = int(version)
        except (TypeError, ValueError):
            version = V4
        if version not in (V4, V6):
            version = V4
        if not 0 <= prefix <= MAX_PREFIX[version]:
            raise InputError(f"Prefix /{prefix} is out of range for IPv{version}.")
        return prefix, version

    if ":" in text:
        try:
            addr = ipaddress.ip_address(text)
        except ValueError as exc:
            raise InputError(f"'{mask}' is not a valid IPv6 mask.") from exc
        return _prefix_from_mask_bits(int(addr), 128, mask), V6

    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise InputError(
            f"'{mask}' is not a valid mask. Try 255.255.255.0, /24, or 24."
        ) from exc
    if addr.version != V4:
        raise InputError("Use an IPv4 dotted mask or a prefix length.")
    mask_int = int(addr)
    if _is_contiguous_mask(mask_int, 32):
        return _prefix_from_mask_bits(mask_int, 32, mask), V4
    inverse = ((1 << 32) - 1) ^ mask_int
    if mask_int != 0 and _is_contiguous_mask(inverse, 32):
        # A dotted wildcard such as 0.0.0.255 — treat it as the inverse mask.
        return _prefix_from_mask_bits(inverse, 32, mask), V4
    raise InputError(
        f"'{mask}' is not a contiguous netmask or wildcard mask."
    )


def mask_info(mask: str, version: int = V4) -> dict[str, Any]:
    prefix, version = parse_mask(mask, version)
    input_kind = _mask_input_kind(mask)
    is_v4 = version == V4
    width = BITS[version]
    zero = ipaddress.ip_network(("0.0.0.0/0" if is_v4 else "::/0"))
    netmask = ipaddress.ip_network(f"{zero.network_address}/{prefix}").netmask
    wildcard_int = ((1 << width) - 1) ^ int(netmask)
    wildcard = (
        ipaddress.IPv4Address(wildcard_int)
        if is_v4
        else ipaddress.IPv6Address(wildcard_int)
    )
    total = 1 << (width - prefix)
    if is_v4:
        if prefix == 32:
            usable = 1
        elif prefix == 31:
            usable = 2
        else:
            usable = max(0, total - 2)
    else:
        usable = total

    reference = []
    if is_v4:
        for p in (8, 16, 24, 25, 26, 27, 28, 29, 30, 31, 32):
            m = ipaddress.ip_network(f"0.0.0.0/{p}").netmask
            t = 1 << (32 - p)
            u = 1 if p == 32 else 2 if p == 31 else max(0, t - 2)
            reference.append(
                {
                    "prefix": p,
                    "netmask": str(m),
                    "wildcard": str(ipaddress.ip_network(f"0.0.0.0/{p}").hostmask),
                    "total_addresses": t,
                    "usable_hosts": u,
                }
            )

    notes: list[str] = []
    if input_kind == "wildcard":
        notes.append(
            f"Read '{mask.strip()}' as a wildcard mask; the equivalent netmask is {netmask}."
        )
    if is_v4 and prefix >= 31:
        notes.append("IPv4 /31 and /32 use all addresses (RFC 3021 host routes).")

    return {
        "kind": "mask",
        "input": mask.strip(),
        "input_kind": input_kind,
        "version": version,
        "prefix": prefix,
        "netmask": str(netmask),
        "netmask_expanded": str(netmask.exploded),
        "wildcard": str(wildcard),
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "usable_hosts": usable,
        "usable_display": f"{usable:,}",
        "binary": {
            "prefix": prefix,
            "netmask_bits": _bits(int(netmask), width),
            "wildcard_bits": _bits(wildcard_int, width),
            "width": width,
        },
        "quick_reference": reference,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------

def _subnet_payload(network: ipaddress._BaseNetwork, index: int) -> dict[str, Any]:
    first, last, usable = _host_bounds(network)
    is_v4 = network.version == V4
    total = network.num_addresses
    return {
        "index": index,
        "cidr": network.with_prefixlen,
        "prefix": network.prefixlen,
        "netmask": str(network.netmask),
        "wildcard": str(network.hostmask),
        "network_address": str(network.network_address),
        "broadcast": str(network.broadcast_address) if is_v4 else None,
        "first_host": str(first),
        "last_host": str(last),
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "usable_hosts": usable,
        "usable_display": f"{usable:,}",
    }


def split_network(
    cidr: str,
    count: int | None = None,
    prefix: int | None = None,
) -> dict[str, Any]:
    _, network, _ = parse_network(cidr)
    if count is None and prefix is None:
        raise InputError("Choose either a subnet count or a new prefix length.")
    if count is not None and prefix is not None:
        raise InputError("Choose a subnet count or a new prefix, not both.")

    notes: list[str] = []
    version = network.version
    if prefix is not None:
        new_prefix = int(prefix)
        if not 0 <= new_prefix <= MAX_PREFIX[version]:
            raise InputError(f"Prefix /{new_prefix} is out of range for IPv{version}.")
        if new_prefix < network.prefixlen:
            raise InputError(
                f"/{new_prefix} is larger than {network.with_prefixlen}; "
                "splitting can only make subnets, not supernets."
            )
        requested_count = 1 << (new_prefix - network.prefixlen)
    else:
        requested_count = int(count)
        if requested_count < 1:
            raise InputError("Subnet count must be at least 1.")
        extra = 0
        while (1 << extra) < requested_count:
            extra += 1
        new_prefix = network.prefixlen + extra
        if new_prefix > MAX_PREFIX[version]:
            raise InputError(
                f"Cannot make {requested_count} subnets from {network.with_prefixlen}."
            )
        if (1 << extra) != requested_count:
            notes.append(
                f"Requested {requested_count} subnets; used /{new_prefix} "
                f"to create the next power of two ({1 << extra})."
            )

    created = 1 << (new_prefix - network.prefixlen)
    if created > MAX_SPLIT:
        raise InputError(
            f"That would create {created:,} subnets (limit {MAX_SPLIT:,}). "
            "Use a smaller split."
        )

    subnets = list(network.subnets(new_prefix=new_prefix))
    return {
        "kind": "split",
        "parent": network.with_prefixlen,
        "version": version,
        "requested_count": requested_count,
        "generated_count": len(subnets),
        "new_prefix": new_prefix,
        "subnets": [_subnet_payload(subnet, i + 1) for i, subnet in enumerate(subnets)],
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# VLSM
# ---------------------------------------------------------------------------

def prefix_for_hosts(hosts: int, version: int = V4) -> int:
    hosts = int(hosts)
    if hosts < 1:
        raise InputError("Host requirements must be at least 1.")
    if version == V4:
        if hosts == 1:
            return 32
        if hosts == 2:
            return 31
        need = hosts + 2
        host_bits = (need - 1).bit_length()
        return max(0, 32 - host_bits)
    host_bits = (hosts - 1).bit_length()
    return max(0, 128 - host_bits)


def _first_subnet(
    network: ipaddress._BaseNetwork, new_prefix: int
) -> tuple[ipaddress._BaseNetwork, list[ipaddress._BaseNetwork]]:
    """Return the first child subnet and a compact list of the remaining space.

    Enumerating every child would explode for IPv6 (a /64 split into /118 has
    2^54 children), so the remainder is summarised into CIDR blocks instead.
    """
    allocated = ipaddress.ip_network(
        f"{network.network_address}/{new_prefix}", strict=False
    )
    rest_start = int(allocated.broadcast_address) + 1
    if rest_start > int(network.broadcast_address):
        return allocated, []
    remainder = list(
        ipaddress.summarize_address_range(
            allocated.broadcast_address + 1, network.broadcast_address
        )
    )
    return allocated, remainder


def vlsm(parent: str, requirements: Sequence[dict[str, Any] | tuple[str, int]]) -> dict[str, Any]:
    _, network, _ = parse_network(parent)
    parsed: list[dict[str, Any]] = []
    for item in requirements:
        if isinstance(item, dict):
            name = str(item.get("name") or "subnet")
            hosts = int(item.get("hosts", 0))
        else:
            name, hosts = item[0], int(item[1])
        if hosts < 1:
            raise InputError(f"'{name}' needs at least one host.")
        parsed.append({"name": name, "hosts": hosts})

    if not parsed:
        raise InputError("Add at least one subnet requirement (name, hosts).")

    ordered = sorted(parsed, key=lambda item: item["hosts"], reverse=True)
    version = network.version
    pool: list[ipaddress._BaseNetwork] = [network]
    allocations: list[dict[str, Any]] = []
    notes: list[str] = []

    for requirement in ordered:
        needed = prefix_for_hosts(requirement["hosts"], version)
        candidates = [net for net in pool if net.prefixlen <= needed]
        if not candidates:
            raise InputError(
                f"Not enough space for '{requirement['name']}' "
                f"({requirement['hosts']} hosts needs /{needed}) in {network.with_prefixlen}."
            )
        chosen = max(candidates, key=lambda net: net.prefixlen)
        pool.remove(chosen)
        if chosen.prefixlen == needed:
            allocated = chosen
        else:
            allocated, remainder = _first_subnet(chosen, needed)
            pool.extend(remainder)

        first, last, usable = _host_bounds(allocated)
        waste = max(0, usable - requirement["hosts"])
        allocations.append(
            {
                "name": requirement["name"],
                "requested_hosts": requirement["hosts"],
                "cidr": allocated.with_prefixlen,
                "network_address": str(allocated.network_address),
                "prefix": allocated.prefixlen,
                "netmask": str(allocated.netmask),
                "wildcard": str(allocated.hostmask),
                "first_host": str(first),
                "last_host": str(last),
                "broadcast": (
                    str(allocated.broadcast_address) if version == V4 else None
                ),
                "usable_hosts": usable,
                "usable_display": f"{usable:,}",
                "waste": waste,
                "waste_display": f"{waste:,}",
            }
        )

    # Show allocations in address order, regardless of request order.
    allocations.sort(key=lambda item: int(ipaddress.ip_address(item["network_address"])))
    total_allocated = sum(
        int(ipaddress.ip_network(item["cidr"]).num_addresses) for item in allocations
    )
    free = sorted(
        ipaddress.collapse_addresses(pool), key=lambda net: int(net.network_address)
    )
    if version == V4 and any(item["prefix"] == 31 for item in allocations):
        notes.append("Two-host subnets use /31 point-to-point links (RFC 3021).")
    notes.append(f"Allocated {total_allocated:,} of {network.num_addresses:,} addresses.")

    return {
        "kind": "vlsm",
        "parent": network.with_prefixlen,
        "version": version,
        "allocations": allocations,
        "free_blocks": [net.with_prefixlen for net in free],
        "free_addresses": sum(net.num_addresses for net in free),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Containment / overlap checks
# ---------------------------------------------------------------------------

def check_relations(target: str, others: Iterable[str]) -> dict[str, Any]:
    _, base, _ = parse_network(target)
    results: list[dict[str, Any]] = []

    for raw in others:
        text = (raw or "").strip()
        if not text:
            continue
        if looks_like_range(text):
            results.append(
                {
                    "input": text,
                    "type": "range",
                    "relation": "unsupported",
                    "contained": False,
                    "note": "Ranges are not supported here; use a CIDR block.",
                }
            )
            continue

        is_network = "/" in text
        try:
            if is_network:
                _, other, _ = parse_network(text)
            else:
                other = ipaddress.ip_address(text)
        except (InputError, ValueError) as exc:
            results.append(
                {
                    "input": text,
                    "type": "invalid",
                    "relation": "invalid",
                    "contained": False,
                    "note": str(exc),
                }
            )
            continue

        if isinstance(other, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if other.version != base.version:
                relation, contained = "different-version", False
                note = f"IPv{other.version} address, but the base is IPv{base.version}."
            else:
                contained = other in base
                relation = "inside" if contained else "outside"
                note = (
                    f"{other} is inside {base.with_prefixlen}."
                    if contained
                    else f"{other} is outside {base.with_prefixlen}."
                )
            results.append(
                {
                    "input": text,
                    "type": "ip",
                    "relation": relation,
                    "contained": contained,
                    "note": note,
                }
            )
        else:
            if other.version != base.version:
                relation, contained = "different-version", False
                note = f"IPv{other.version} block, but the base is IPv{base.version}."
            elif other.subnet_of(base):
                relation, contained = "subnet", True
                note = f"{other.with_prefixlen} is a subnet of {base.with_prefixlen}."
            elif base.subnet_of(other):
                relation, contained = "supernet", False
                note = f"{other.with_prefixlen} is a supernet of {base.with_prefixlen}."
            elif base.overlaps(other):
                relation, contained = "overlap", False
                note = f"{other.with_prefixlen} partially overlaps {base.with_prefixlen}."
            else:
                relation, contained = "disjoint", False
                note = f"{other.with_prefixlen} is disjoint from {base.with_prefixlen}."
            results.append(
                {
                    "input": text,
                    "type": "network",
                    "relation": relation,
                    "contained": contained,
                    "note": note,
                }
            )

    return {
        "kind": "check",
        "base": base.with_prefixlen,
        "version": base.version,
        "results": results,
        "any_contained": any(result["contained"] for result in results),
        "any_overlap": any(
            result["relation"] in ("subnet", "supernet", "overlap", "inside")
            for result in results
        ),
    }
