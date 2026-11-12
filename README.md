# subnetkit

A fast, dependency-free IP and subnet calculator for **IPv4 and IPv6** — CIDR
inspection, address ranges, netmask/wildcard conversion, equal subnet
splitting, VLSM allocation, and containment checks.

It ships with two front ends that share the same calculation core:

- a rich terminal CLI
- a local web UI (Python standard library server, no external assets)

Everything runs offline.

## Quick start

From this directory:

```bash
./bin/subnetkit 192.168.1.10/24
./bin/subnetkit web
```

Or use the package directly:

```bash
python -m subnetkit 10.0.0.0/8
python -m subnetkit web --port 8765
```

Install it on your `PATH` if you like:

```bash
pip install -e .
subnetkit 192.168.1.10/24
```

The web UI starts at <http://localhost:8765> and opens a browser automatically
(use `--no-open` to skip that).

## What it does

### Inspect a CIDR block, host, or range

```bash
$ subnetkit 192.168.1.10/24
  192.168.1.0/24  IPv4 · Private
  ────────────────────────────────────────────────────────────
  Address         192.168.1.10
  Network         192.168.1.0
  Netmask         255.255.255.0  /24
  Wildcard        0.0.0.255
  Host range      192.168.1.1 – 192.168.1.254
  Broadcast       192.168.1.255
  Usable hosts    254 usable  ·  2^8 total
  Class           C
  Scope           Private
  Address bits    11000000 10101000 00000001 00001010
                  network / host

  · Host bits were cleared: 192.168.1.10 is inside 192.168.1.0/24.
```

Accepted inputs:

| Input | Meaning |
| --- | --- |
| `192.168.1.10/24` | CIDR block, host bits allowed |
| `192.168.1.10` | Host address; classful default (`/8`, `/16`, or `/24`) |
| `2001:db8::1/64` | IPv6; bare addresses default to `/64` |
| `172.16.5.4 255.255.240.0` | Address plus dotted netmask |
| `10.0.0.5 - 10.0.0.42` | Address range → minimal CIDR list |
| `10.0.0.5 to 10.0.0.42` | Same, using `to` |

Ranges are summarised into the smallest possible set of CIDR blocks and include
the range's common prefix.

### Split networks

```bash
$ subnetkit split 192.168.1.0/24 -n 4
$ subnetkit split 10.0.0.0/16 -p 24
```

`-n/--count` creates the next power of two and explains the result when the
requested count is not a power of two. `-p/--prefix` creates every subnet at
the requested prefix. Output is capped at 4,096 rows; use `--json` for scripts.

### Convert masks

```bash
$ subnetkit mask 255.255.255.192
$ subnetkit mask /26
$ subnetkit mask 0.0.0.255          # read as a wildcard
$ subnetkit mask 64 --ipv6
```

Shows prefix, netmask, wildcard, total addresses, usable hosts, binary mask,
and a quick IPv4 reference table. Non-contiguous masks are rejected with an
explanation.

### VLSM allocation

```bash
$ subnetkit vlsm 192.168.1.0/24 LAN:100 WAN:2 Guest:20
  192.168.1.0/24  VLSM · 3 allocations
  ────────────────────────────────────────────────────────────
  Name   Needs  Allocated         Usable  Waste  Host range
  ─────  ─────  ────────────────  ──────  ─────  ─────────────────────────────
  LAN      100  192.168.1.0/25       126     26  192.168.1.1 – 192.168.1.126
  Guest     20  192.168.1.128/27      30     10  192.168.1.129 – 192.168.1.158
  WAN        2  192.168.1.160/31       2      0  192.168.1.160 – 192.168.1.161
```

Largest requirements are placed first using a best-fit strategy, and the
remaining free space is collapsed into clean CIDR blocks. Two-host IPv4
subnets use `/31` point-to-point links (RFC 3021).

### Check containment and overlap

```bash
$ subnetkit check 10.0.0.0/8 10.1.2.3 192.168.0.0/16
```

Classifies each value as `inside`, `outside`, `subnet`, `supernet`,
`disjoint`, or `different-version`.

### JSON output

Every command accepts `--json`:

```bash
subnetkit split 10.0.0.0/16 -p 24 --json
subnetkit mask /26 --json
subnetkit --json 192.168.1.10/24
```

## Web UI

```bash
subnetkit web --host 127.0.0.1 --port 8765
```

Tabs for **Inspect**, **Split**, **Masks**, **VLSM**, and **Check**, with live
results, copy buttons, binary network/host bit visualisation, and a responsive
layout. The server binds to `127.0.0.1` by default and makes no external
requests.

Use `--host 0.0.0.0` if you explicitly want to expose it on your LAN.

## Semantics and edge cases

- **Host counts** exclude the network and broadcast address for IPv4 prefixes
  `/0`–`/30`. `/31` counts both addresses (RFC 3021) and `/32` counts one.
- **IPv6** has no broadcast address; all addresses in a subnet are reported as
  usable (the subnet-router anycast address is a protocol detail, not a
  reservation).
- **Bare IPv4 addresses** use the historical classful default so
  `192.168.1.10` behaves like `/24`. The CLI and UI label this as assumed.
- **Wildcard masks** such as `0.0.0.255` are recognised when the value is the
  exact inverse of a contiguous netmask.
- **Ranges** may be reversed; they are swapped with a note.
- **Split limit** is 4,096 generated subnets to keep terminal and browser
  output sensible.

## Development

```bash
python -m unittest discover -s tests -v
```

Layout:

```
subnetkit/
  core.py            all calculations (stdlib ipaddress only)
  cli.py             argparse CLI and terminal rendering
  web.py             local HTTP server and JSON API
  static/            index.html, styles.css, app.js
tests/test_core.py   unit tests for every calculator
bin/subnetkit        run-from-checkout wrapper
```

No runtime dependencies. Python 3.9+.
