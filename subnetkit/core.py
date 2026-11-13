"""Core IP / subnet calculations for subnetkit.

Only the Python standard library is used.  Every public function returns
plain, JSON-serialisable dictionaries so the same logic powers the CLI and
the local web UI.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections.abc import Iterable, Sequence
from typing import Any, Union, cast

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

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

def _summarize_range(first: IPAddress, last: IPAddress) -> list[IPNetwork]:
    """Summarise an address range while narrowing to one IP version."""
    if first.version != last.version:
        raise InputError("Range start and end must be the same IP version.")
    if isinstance(first, ipaddress.IPv4Address) and isinstance(
        last, ipaddress.IPv4Address
    ):
        return list(ipaddress.summarize_address_range(first, last))
    if isinstance(first, ipaddress.IPv6Address) and isinstance(
        last, ipaddress.IPv6Address
    ):
        return list(ipaddress.summarize_address_range(first, last))
    raise InputError("Range start and end must be the same IP version.")


def _collapse_networks(networks: Iterable[IPNetwork]) -> list[IPNetwork]:
    items = list(networks)
    if not items:
        return []
    if items[0].version == V4:
        return list(
            ipaddress.collapse_addresses(
                cast(list[ipaddress.IPv4Network], items)
            )
        )
    return list(
        ipaddress.collapse_addresses(
            cast(list[ipaddress.IPv6Network], items)
        )
    )


def _subnets(network: IPNetwork, new_prefix: int) -> list[IPNetwork]:
    if isinstance(network, ipaddress.IPv4Network):
        return list(network.subnets(new_prefix=new_prefix))
    return list(network.subnets(new_prefix=new_prefix))


def _is_subnet(inner: IPNetwork, outer: IPNetwork) -> bool:
    if inner.version != outer.version:
        return False
    if isinstance(inner, ipaddress.IPv4Network):
        return isinstance(outer, ipaddress.IPv4Network) and inner.subnet_of(outer)
    return isinstance(outer, ipaddress.IPv6Network) and inner.subnet_of(outer)


def _overlaps(left: IPNetwork, right: IPNetwork) -> bool:
    if left.version != right.version:
        return False
    if isinstance(left, ipaddress.IPv4Network):
        return isinstance(right, ipaddress.IPv4Network) and left.overlaps(right)
    return isinstance(right, ipaddress.IPv6Network) and left.overlaps(right)


def _pow2_label(n: int) -> str | None:
    if n > 0 and (n & (n - 1)) == 0:
        return f"2^{n.bit_length() - 1}"
    return None


def _default_prefix(ip: IPAddress) -> int:
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
    # Accept "192.168.1.10 / 24" as well as "192.168.1.10/24".
    text = re.sub(r"\s*/\s*", "/", text)
    parts = text.split()
    if len(parts) == 2 and "/" not in parts[0]:
        # "192.168.1.10 255.255.255.0"
        text = f"{parts[0]}/{parts[1]}"
    elif len(parts) > 1:
        raise InputError("Too many values — use 'address/prefix' or 'address mask'.")
    return text


def _address_error(text: str, exc: ValueError) -> str:
    if "%" in text:
        return (
            "IPv6 zone IDs are not supported; remove the "
            f"'%<zone>' suffix from '{text}'."
        )
    if re.search(r"(?:^|\.)0\d", text):
        return f"IPv4 octets must not have leading zeros: '{text}'."
    return f"'{text}' is not a valid IP address or CIDR block."


def _validate_prefix(address: IPAddress, prefix_text: str) -> str:
    """Validate a prefix and return the canonical address/prefix string."""
    if not prefix_text:
        raise InputError(
            "Missing prefix after '/'. Use address/prefix, such as 192.168.1.1/24."
        )
    if re.fullmatch(r"[+-]?\d+", prefix_text):
        prefix = int(prefix_text)
        max_prefix = MAX_PREFIX[address.version]
        if prefix < 0:
            raise InputError(
                f"Prefix /{prefix} is invalid for IPv{address.version}; "
                f"must be between /0 and /{max_prefix}."
            )
        if prefix > max_prefix:
            raise InputError(
                f"Prefix /{prefix} is invalid for IPv{address.version}, "
                f"max is /{max_prefix}."
            )
        return f"{address}/{prefix}"
    if "." in prefix_text or ":" in prefix_text:
        # A dotted IPv4 netmask (or an IPv6 mask) is validated by ipaddress.
        return f"{address}/{prefix_text}"
    raise InputError(f"Prefix '{prefix_text}' is not a number.")


def looks_like_range(text: str) -> bool:
    return bool(_RANGE_RE.match((text or "").strip()))


def _parse_range(text: str) -> tuple[IPAddress, IPAddress]:
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


def parse_network(text: str) -> tuple[IPAddress, IPNetwork, bool]:
    """Parse a CIDR/host input, returning (address, network, assumed_prefix)."""
    text = _normalise_input(text)

    if "/" in text:
        if text.count("/") > 1:
            raise InputError("Use exactly one '/' in a CIDR block.")
        addr_part, prefix_part = text.split("/", 1)
        if not addr_part:
            raise InputError(
                "Missing address before '/'. Use address/prefix, such as 192.168.1.1/24."
            )
        if "%" in addr_part:
            raise InputError(
                "IPv6 zone IDs are not supported; remove the "
                f"'%<zone>' suffix from '{addr_part}'."
            )
        try:
            address = ipaddress.ip_address(addr_part)
        except ValueError as exc:
            raise InputError(_address_error(addr_part, exc)) from exc
        cidr_text = _validate_prefix(address, prefix_part)
        try:
            network = ipaddress.ip_network(cidr_text, strict=False)
        except ValueError as exc:
            raise InputError(f"Invalid CIDR block '{text}': {exc}") from exc
        assumed = False
    else:
        if "%" in text:
            raise InputError(
                "IPv6 zone IDs are not supported; remove the "
                f"'%<zone>' suffix from '{text}'."
            )
        try:
            address = ipaddress.ip_address(text)
        except ValueError as exc:
            raise InputError(_address_error(text, exc)) from exc
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


def _scope_for_address(address: IPAddress) -> str:
    specials = _SPECIAL_V4_NETS if address.version == V4 else _SPECIAL_V6_NETS
    matches = [
        (special.prefixlen, label)
        for special, label in specials
        if address in special
    ]
    if matches:
        return max(matches, key=lambda item: item[0])[1]
    return "Public" if address.version == V4 else "Global unicast"


def _scope_for_network(network: IPNetwork) -> str:
    specials = _SPECIAL_V4_NETS if network.version == V4 else _SPECIAL_V6_NETS
    containing = [
        (special.prefixlen, label)
        for special, label in specials
        if _is_subnet(network, special)
    ]
    if containing:
        return max(containing, key=lambda item: item[0])[1]
    if any(_overlaps(network, special) for special, _ in specials):
        return "Spans multiple ranges"
    return "Public" if network.version == V4 else "Global unicast"


def _scope(
    network: IPNetwork,
    address: IPAddress | None = None,
) -> str:
    # A bare host is classified by the address the user typed; a CIDR block is
    # classified only if the whole block fits inside one special range.
    if address is not None:
        return _scope_for_address(address)
    return _scope_for_network(network)


_SCOPE_FLAGS = {
    "This network": ["Reserved"],
    "Private": ["Private"],
    "Shared (CGNAT)": ["Shared"],
    "Loopback": ["Loopback"],
    "Link-local": ["Link-local"],
    "IETF protocol": ["IETF"],
    "Documentation": ["Documentation"],
    "6to4 relay": ["6to4"],
    "Benchmarking": ["Benchmarking"],
    "Multicast": ["Multicast"],
    "Limited broadcast": ["Broadcast"],
    "Reserved": ["Reserved"],
    "Unspecified": ["Unspecified"],
    "IPv4-mapped": ["IPv4-mapped"],
    "NAT64": ["NAT64"],
    "Discard": ["Discard"],
    "ORCHID": ["ORCHID"],
    "6to4": ["6to4"],
    "Unique local": ["Private"],
    "Public": ["Global"],
    "Global unicast": ["Global"],
    "Global": ["Global"],
    "Spans multiple ranges": [],
}


def _flags(scope: str) -> list[str]:
    return list(_SCOPE_FLAGS.get(scope, [scope]))


def _host_bounds(network: IPNetwork) -> tuple[IPAddress, IPAddress, int]:
    total = network.num_addresses
    if network.version == V4:
        if network.prefixlen >= 31:
            return network.network_address, network.broadcast_address, total
        return network.network_address + 1, network.broadcast_address - 1, max(0, total - 2)
    return network.network_address, network.broadcast_address, total


def _bits(value: int, width: int) -> str:
    return format(value, f"0{width}b")


def _binary_info(
    address: IPAddress, network: IPNetwork, netmask: IPAddress
) -> dict[str, Any]:
    width = BITS[network.version]
    return {
        "prefix": network.prefixlen,
        "address_bits": _bits(int(address), width),
        "network_bits": _bits(int(network.network_address), width),
        "netmask_bits": _bits(int(netmask), width),
        "width": width,
    }


def _eui64_info(address: IPAddress) -> tuple[str | None, str | None]:
    if address.version != V6:
        return None, None
    interface_id = int(address) & ((1 << 64) - 1)
    groups = [
        (interface_id >> (48 - 16 * index)) & 0xFFFF
        for index in range(4)
    ]
    value = ":".join(f"{group:04x}" for group in groups)
    link_local = ipaddress.IPv6Address((0xFE80 << 112) | interface_id)
    hint = (
        f"Modified EUI-64 interface ID: {value}. "
        "Flip the U/L bit (first byte XOR 0x02) and insert ff:fe "
        "to recover a MAC address; the link-local form is "
        f"{link_local.compressed}."
    )
    return value, hint


def _network_payload(
    address: IPAddress,
    network: IPNetwork,
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

    scope = _scope(network, address if assumed else None)
    attribute_source = address if assumed else network
    is_private = bool(attribute_source.is_private)
    is_global = bool(attribute_source.is_global)
    if scope == "Spans multiple ranges":
        # A block that covers both special and ordinary space is neither
        # wholly private nor wholly global.
        is_private = False
        is_global = False

    host_offset = int(address) - int(network.network_address)
    integer = int(address)
    hex_digits = BITS[version] // 4
    eui64, eui64_hint = _eui64_info(address)

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
        "host_offset": host_offset,
        "host_number": host_offset + 1,
        "host_total": total,
        "host_position": f"host #{host_offset + 1} of {total}",
        "host_position_display": f"host #{host_offset + 1:,} of {total:,}",
        "position": f"host #{host_offset + 1} of {total}",
        "first_host": str(first),
        "last_host": str(last),
        "broadcast": str(network.broadcast_address) if is_v4 else None,
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "usable_hosts": usable,
        "usable_display": f"{usable:,}",
        "class": _ipv4_class(cast(ipaddress.IPv4Address, address)) if is_v4 else None,
        "scope": scope,
        "flags": _flags(scope),
        "is_private": is_private,
        "is_global": is_global,
        "reverse_dns": address.reverse_pointer,
        "reverse_dns_name": address.reverse_pointer,
        "reverse_pointer": address.reverse_pointer,
        "integer": integer,
        "integer_form": integer,
        "integer_display": str(integer),
        "decimal": integer,
        "hex": hex(integer),
        "hex_padded": f"0x{integer:0{hex_digits}x}",
        "hex_form": f"0x{integer:0{hex_digits}x}",
        "ipv6_compressed": str(address) if not is_v4 else None,
        "ipv6_expanded": address.exploded if not is_v4 else None,
        "compressed": str(address) if not is_v4 else None,
        "expanded": address.exploded if not is_v4 else None,
        "eui64": eui64,
        "eui64_hint": eui64_hint,
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
    blocks = _summarize_range(start, end)
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
# Set operations: merge / exclude / diff
# ---------------------------------------------------------------------------

def _as_items(value: Iterable[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [
            part.strip()
            for line in value.splitlines()
            for part in line.split(",")
            if part.strip()
        ]
    return [str(item).strip() for item in value if str(item).strip()]


def _networks_for_item(raw: str) -> list[IPNetwork]:
    """Parse one CIDR/host/range input as a list of networks.

    Bare addresses represent a single host here (unlike ``describe``),
    because set operations should not silently expand them to classful blocks.
    """
    text = (raw or "").strip()
    if not text:
        return []
    if looks_like_range(text):
        start, end = _parse_range(text)
        if int(start) > int(end):
            start, end = end, start
        return _summarize_range(start, end)
    address, network, assumed = parse_network(text)
    if assumed:
        network = ipaddress.ip_network(
            f"{address}/{MAX_PREFIX[address.version]}", strict=False
        )
    return [network]


def _networks_for_items(value: Iterable[str] | str | None) -> list[IPNetwork]:
    networks: list[IPNetwork] = []
    for raw in _as_items(value):
        networks.extend(_networks_for_item(raw))
    return networks


def _normalise_intervals(
    intervals: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    ordered = sorted(intervals)
    if not ordered:
        return []
    merged: list[list[int]] = [[ordered[0][0], ordered[0][1]]]
    for start, end in ordered[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def _subtract_intervals(
    base: Iterable[tuple[int, int]],
    remove: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    removals = _normalise_intervals(remove)
    result: list[tuple[int, int]] = []
    for start, end in _normalise_intervals(base):
        pieces = [(start, end)]
        for remove_start, remove_end in removals:
            if remove_end < start or remove_start > end:
                continue
            next_pieces: list[tuple[int, int]] = []
            for piece_start, piece_end in pieces:
                if remove_end < piece_start or remove_start > piece_end:
                    next_pieces.append((piece_start, piece_end))
                    continue
                if piece_start < remove_start:
                    next_pieces.append((piece_start, remove_start - 1))
                if remove_end < piece_end:
                    next_pieces.append((remove_end + 1, piece_end))
            pieces = next_pieces
        result.extend(pieces)
    return result


def _intersect_intervals(
    left: Iterable[tuple[int, int]],
    right: Iterable[tuple[int, int]],
) -> list[tuple[int, int]]:
    left_intervals = _normalise_intervals(left)
    right_intervals = _normalise_intervals(right)
    result: list[tuple[int, int]] = []
    left_index = right_index = 0
    while left_index < len(left_intervals) and right_index < len(right_intervals):
        left_start, left_end = left_intervals[left_index]
        right_start, right_end = right_intervals[right_index]
        start = max(left_start, right_start)
        end = min(left_end, right_end)
        if start <= end:
            result.append((start, end))
        if left_end < right_end:
            left_index += 1
        else:
            right_index += 1
    return result


def _intervals_to_cidrs(
    intervals: Iterable[tuple[int, int]], version: int
) -> list[IPNetwork]:
    blocks: list[IPNetwork] = []
    for start, end in _normalise_intervals(intervals):
        if version == V4:
            blocks.extend(
                _summarize_range(
                    ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
                )
            )
        else:
            blocks.extend(
                _summarize_range(
                    ipaddress.IPv6Address(start), ipaddress.IPv6Address(end)
                )
            )
    return sorted(blocks, key=lambda network: int(network.network_address))


def _networks_to_intervals(
    networks: Iterable[IPNetwork],
) -> list[tuple[int, int]]:
    return _normalise_intervals(
        (int(network.network_address), int(network.broadcast_address))
        for network in networks
    )


def merge(
    items: Iterable[str] | str | None = None,
    *more: str,
) -> dict[str, Any]:
    """Collapse any mix of CIDRs, hosts, and ranges into minimal CIDR blocks."""
    raw_items = _as_items(items)
    for extra in more:
        raw_items.extend(_as_items(extra))
    networks: list[IPNetwork] = []
    for raw in raw_items:
        networks.extend(_networks_for_item(raw))

    versions = {network.version for network in networks}
    if len(versions) > 1:
        raise InputError("Cannot merge IPv4 and IPv6 networks together.")
    version = next(iter(versions), None)
    blocks = (
        sorted(
            _collapse_networks(networks),
            key=lambda network: int(network.network_address),
        )
        if networks
        else []
    )
    total = sum(network.num_addresses for network in blocks)

    notes: list[str] = []
    if not raw_items:
        notes.append("No networks were supplied; the merged result is empty.")
    elif len(blocks) < len(networks):
        notes.append(
            f"Collapsed {len(networks)} input block"
            f"{'s' if len(networks) != 1 else ''} into "
            f"{len(blocks)} block{'s' if len(blocks) != 1 else ''}."
        )

    cidrs = [block.with_prefixlen for block in blocks]
    return {
        "kind": "merge",
        "version": version,
        "inputs": raw_items,
        "input_count": len(raw_items),
        "expanded_count": len(networks),
        "cidr_list": cidrs,
        "cidrs": cidrs,
        "merged": cidrs,
        "cidr_count": len(blocks),
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "notes": notes,
    }


def exclude(
    base: str,
    items: Iterable[str] | str | None = None,
    *more: str,
) -> dict[str, Any]:
    """Carve CIDRs/ranges out of a base network."""
    _, base_network, _ = parse_network(base)
    raw_items = _as_items(items)
    for extra in more:
        raw_items.extend(_as_items(extra))
    notes: list[str] = []
    removals: list[tuple[int, int]] = []

    for raw in raw_items:
        for network in _networks_for_item(raw):
            if network.version != base_network.version:
                notes.append(
                    f"Ignored {network.with_prefixlen}: different IP version."
                )
                continue
            if not _overlaps(network, base_network):
                notes.append(
                    f"Ignored {network.with_prefixlen}: outside "
                    f"{base_network.with_prefixlen}."
                )
                continue
            removals.append(
                (
                    max(
                        int(base_network.network_address),
                        int(network.network_address),
                    ),
                    min(
                        int(base_network.broadcast_address),
                        int(network.broadcast_address),
                    ),
                )
            )

    all_addresses = [
        (
            int(base_network.network_address),
            int(base_network.broadcast_address),
        )
    ]
    remaining = _subtract_intervals(all_addresses, removals)
    blocks = _intervals_to_cidrs(remaining, base_network.version)
    total = sum(network.num_addresses for network in blocks)
    removed = base_network.num_addresses - total

    if not raw_items:
        notes.append("No exclusions were supplied; the base network is unchanged.")
    if not blocks:
        notes.append("Every address in the base network was excluded.")

    cidrs = [block.with_prefixlen for block in blocks]
    return {
        "kind": "exclude",
        "base": base_network.with_prefixlen,
        "version": base_network.version,
        "excluded": raw_items,
        "cidr_list": cidrs,
        "cidrs": cidrs,
        "remaining": cidrs,
        "cidr_count": len(blocks),
        "total_addresses": total,
        "total_display": f"{total:,}",
        "total_power": _pow2_label(total),
        "removed_addresses": removed,
        "removed_display": f"{removed:,}",
        "notes": notes,
    }


def _input_label(value: Iterable[str] | str | None) -> str:
    if isinstance(value, str):
        return value.strip()
    return ", ".join(_as_items(value))


def diff(
    a: Iterable[str] | str | None = None,
    b: Iterable[str] | str | None = None,
) -> dict[str, Any]:
    """Return addresses only in A, only in B, and in both."""
    a_networks = _networks_for_items(a)
    b_networks = _networks_for_items(b)
    versions = {network.version for network in a_networks + b_networks}
    if len(versions) > 1:
        raise InputError("Cannot diff IPv4 and IPv6 networks together.")
    version = next(iter(versions), None)

    a_intervals = _networks_to_intervals(a_networks)
    b_intervals = _networks_to_intervals(b_networks)
    only_a_blocks = (
        _intervals_to_cidrs(
            _subtract_intervals(a_intervals, b_intervals), version
        )
        if version is not None
        else []
    )
    only_b_blocks = (
        _intervals_to_cidrs(
            _subtract_intervals(b_intervals, a_intervals), version
        )
        if version is not None
        else []
    )
    both_blocks = (
        _intervals_to_cidrs(_intersect_intervals(a_intervals, b_intervals), version)
        if version is not None
        else []
    )

    only_a_addresses = sum(network.num_addresses for network in only_a_blocks)
    only_b_addresses = sum(network.num_addresses for network in only_b_blocks)
    both_addresses = sum(network.num_addresses for network in both_blocks)

    notes: list[str] = []
    if version is None:
        notes.append("Both inputs are empty.")
    elif not only_a_blocks and not only_b_blocks:
        notes.append("A and B contain exactly the same addresses.")
    elif not both_blocks:
        notes.append("A and B do not overlap.")

    only_a = [network.with_prefixlen for network in only_a_blocks]
    only_b = [network.with_prefixlen for network in only_b_blocks]
    both = [network.with_prefixlen for network in both_blocks]
    return {
        "kind": "diff",
        "a": _input_label(a),
        "b": _input_label(b),
        "version": version,
        "only_a": only_a,
        "only_b": only_b,
        "both": both,
        "only_in_a": only_a,
        "only_in_b": only_b,
        "in_both": both,
        "a_only": only_a,
        "b_only": only_b,
        "intersection": both,
        "only_a_count": len(only_a_blocks),
        "only_b_count": len(only_b_blocks),
        "both_count": len(both_blocks),
        "only_a_addresses": only_a_addresses,
        "only_b_addresses": only_b_addresses,
        "both_addresses": both_addresses,
        "total_addresses": only_a_addresses + only_b_addresses + both_addresses,
        "notes": notes,
    }



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
    zero = ipaddress.ip_network("0.0.0.0/0" if is_v4 else "::/0")
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

def _subnet_payload(network: IPNetwork, index: int) -> dict[str, Any]:
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
        assert count is not None
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

    subnets = _subnets(network, new_prefix)
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

def _validate_growth(growth: int | float) -> float:
    try:
        value = float(growth)
    except (TypeError, ValueError) as exc:
        raise InputError("Growth must be a non-negative percentage.") from exc
    if not math.isfinite(value) or value < 0:
        raise InputError("Growth must be a non-negative percentage.")
    return value


def _effective_hosts(
    hosts: int, growth: float = 0.0, gateway: bool = False
) -> int:
    grown = math.ceil(hosts * (1 + growth / 100.0))
    if gateway:
        grown += 1
    return max(1, grown)


def prefix_for_hosts(
    hosts: int,
    version: int = V4,
    *,
    classic: bool = False,
    gateway: bool = False,
    growth: int | float = 0,
) -> int:
    hosts = int(hosts)
    if hosts < 1:
        raise InputError("Host requirements must be at least 1.")
    growth = _validate_growth(growth)
    effective = _effective_hosts(hosts, growth, gateway)
    if version == V4:
        if classic and effective <= 2:
            # Classic subnetting always leaves room for network/broadcast;
            # one- and two-host requirements both receive a /30.
            return 30
        if effective == 1:
            return 32
        if effective == 2:
            return 31
        need = effective + 2
        host_bits = (need - 1).bit_length()
        return max(0, 32 - host_bits)
    host_bits = (effective - 1).bit_length()
    return max(0, 128 - host_bits)


def _first_subnet(
    network: IPNetwork, new_prefix: int
) -> tuple[IPNetwork, list[IPNetwork]]:
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
    remainder = _summarize_range(
        allocated.broadcast_address + 1, network.broadcast_address
    )
    return allocated, remainder


def _no_space_error(
    name: str,
    hosts: int,
    needed: int,
    network: IPNetwork,
    pool: Sequence[IPNetwork],
    version: int,
) -> InputError:
    """Build a VLSM failure message that explains the actual shortfall."""
    required = 1 << (MAX_PREFIX[version] - needed)
    if not pool:
        return InputError(
            f"Not enough space for '{name}': {hosts:,} hosts need "
            f"{required:,} addresses (/{needed}), but no free blocks remain "
            f"in {network.with_prefixlen} (the largest free block is "
            f"none; short {required:,} addresses)."
        )

    largest = max(pool, key=lambda net: net.num_addresses)
    shortfall = max(0, required - largest.num_addresses)
    total_free = sum(net.num_addresses for net in pool)
    return InputError(
        f"Not enough space for '{name}': {hosts:,} hosts need "
        f"{required:,} addresses (/{needed}), but the largest free block is "
        f"{largest.with_prefixlen} with {largest.num_addresses:,} addresses "
        f"— short {shortfall:,} addresses. Total free: {total_free:,} "
        f"address{'es' if total_free != 1 else ''} in {len(pool)} "
        f"block{'s' if len(pool) != 1 else ''}."
    )


def vlsm(
    parent: str,
    requirements: Sequence[dict[str, Any] | tuple[str, int]],
    *,
    classic: bool = False,
    gateway: bool = False,
    growth: int | float = 0,
) -> dict[str, Any]:
    _, network, _ = parse_network(parent)
    growth = _validate_growth(growth)
    parsed: list[dict[str, Any]] = []
    for item in requirements:
        if isinstance(item, dict):
            name = str(item.get("name") or "subnet")
            hosts = int(item.get("hosts", 0))
        else:
            name, hosts = item[0], int(item[1])
        if hosts < 1:
            raise InputError(f"'{name}' needs at least one host.")
        parsed.append(
            {
                "name": name,
                "hosts": hosts,
                "effective_hosts": _effective_hosts(hosts, growth, gateway),
            }
        )

    if not parsed:
        raise InputError("Add at least one subnet requirement (name, hosts).")

    ordered = sorted(
        parsed, key=lambda item: item["effective_hosts"], reverse=True
    )
    version = network.version
    pool: list[IPNetwork] = [network]
    allocations: list[dict[str, Any]] = []
    notes: list[str] = []
    if classic and version == V4:
        notes.append(
            "Classic mode: one- and two-host subnets use /30; "
            "/31 and /32 are not allocated."
        )
    if gateway:
        notes.append("One address per subnet is reserved for a gateway.")
    if growth:
        notes.append(
            f"Requirements were inflated by {growth:g}% before allocation."
        )

    for requirement in ordered:
        needed = prefix_for_hosts(
            requirement["hosts"],
            version,
            classic=classic,
            gateway=gateway,
            growth=growth,
        )
        candidates = [net for net in pool if net.prefixlen <= needed]
        if not candidates:
            raise _no_space_error(
                requirement["name"],
                requirement["effective_hosts"],
                needed,
                network,
                pool,
                version,
            )
        chosen = max(candidates, key=lambda net: net.prefixlen)
        pool.remove(chosen)
        if chosen.prefixlen == needed:
            allocated = chosen
        else:
            allocated, remainder = _first_subnet(chosen, needed)
            pool.extend(remainder)

        first, last, usable = _host_bounds(allocated)
        effective = requirement["effective_hosts"]
        waste = max(0, usable - effective)
        allocations.append(
            {
                "name": requirement["name"],
                "requested_hosts": requirement["hosts"],
                "effective_hosts": effective,
                "planned_hosts": effective,
                "gateway_reserved": 1 if gateway else 0,
                "growth": growth,
                "growth_percent": growth,
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
        _collapse_networks(pool), key=lambda net: int(net.network_address)
    )
    if version == V4 and any(item["prefix"] == 31 for item in allocations):
        notes.append("Two-host subnets use /31 point-to-point links (RFC 3021).")
    notes.append(f"Allocated {total_allocated:,} of {network.num_addresses:,} addresses.")

    return {
        "kind": "vlsm",
        "parent": network.with_prefixlen,
        "version": version,
        "classic": bool(classic),
        "gateway": bool(gateway),
        "growth": growth,
        "growth_percent": growth,
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
            try:
                start, end = _parse_range(text)
                if int(start) > int(end):
                    start, end = end, start
                blocks = _summarize_range(start, end)
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

            if blocks[0].version != base.version:
                relation, contained = "different-version", False
                note = (
                    f"IPv{blocks[0].version} range, but the base is "
                    f"IPv{base.version}."
                )
                block_results = [
                    {
                        "cidr": block.with_prefixlen,
                        "relation": "different-version",
                        "contained": False,
                    }
                    for block in blocks
                ]
            else:
                block_results = []
                relations: list[str] = []
                for block in blocks:
                    if _is_subnet(block, base):
                        block_relation, block_contained = "subnet", True
                    elif _is_subnet(base, block):
                        block_relation, block_contained = "supernet", False
                    elif _overlaps(base, block):
                        block_relation, block_contained = "overlap", False
                    else:
                        block_relation, block_contained = "disjoint", False
                    relations.append(block_relation)
                    block_results.append(
                        {
                            "cidr": block.with_prefixlen,
                            "relation": block_relation,
                            "contained": block_contained,
                        }
                    )

                if all(relation_name == "subnet" for relation_name in relations):
                    relation, contained = "inside", True
                    note = (
                        f"{text} expands to {len(blocks)} CIDR block"
                        f"{'s' if len(blocks) != 1 else ''}; all are inside "
                        f"{base.with_prefixlen}."
                    )
                elif all(relation_name == "disjoint" for relation_name in relations):
                    relation, contained = "outside", False
                    note = (
                        f"{text} expands to {len(blocks)} CIDR block"
                        f"{'s' if len(blocks) != 1 else ''}; none overlap "
                        f"{base.with_prefixlen}."
                    )
                elif len(relations) == 1 and relations[0] in ("supernet", "overlap"):
                    relation, contained = relations[0], False
                    note = (
                        f"{text} expands to {blocks[0].with_prefixlen}, which "
                        f"{'contains' if relation == 'supernet' else 'partially overlaps'} "
                        f"{base.with_prefixlen}."
                    )
                else:
                    relation, contained = "overlap", False
                    inside_count = relations.count("subnet")
                    overlap_count = sum(
                        relation_name in ("overlap", "supernet")
                        for relation_name in relations
                    )
                    note = (
                        f"{text} expands to {len(blocks)} CIDR blocks; "
                        f"{inside_count} inside, {overlap_count} overlapping, "
                        f"and {len(blocks) - inside_count - overlap_count} outside "
                        f"{base.with_prefixlen}."
                    )

            results.append(
                {
                    "input": text,
                    "type": "range",
                    "relation": relation,
                    "contained": contained,
                    "note": note,
                    "cidr_list": [block.with_prefixlen for block in blocks],
                    "block_count": len(blocks),
                    "blocks": block_results,
                }
            )
            continue

        is_network = "/" in text
        other: IPAddress | IPNetwork
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
            other_network = cast(IPNetwork, other)
            if other_network.version != base.version:
                relation, contained = "different-version", False
                note = (
                    f"IPv{other_network.version} block, but the base is "
                    f"IPv{base.version}."
                )
            elif _is_subnet(other_network, base):
                relation, contained = "subnet", True
                note = (
                    f"{other_network.with_prefixlen} is a subnet of "
                    f"{base.with_prefixlen}."
                )
            elif _is_subnet(base, other_network):
                relation, contained = "supernet", False
                note = (
                    f"{other_network.with_prefixlen} is a supernet of "
                    f"{base.with_prefixlen}."
                )
            elif _overlaps(base, other_network):
                relation, contained = "overlap", False
                note = (
                    f"{other_network.with_prefixlen} partially overlaps "
                    f"{base.with_prefixlen}."
                )
            else:
                relation, contained = "disjoint", False
                note = (
                    f"{other_network.with_prefixlen} is disjoint from "
                    f"{base.with_prefixlen}."
                )
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
