# subnetkit

A fast, dependency-free IP and subnet calculator for **IPv4 and IPv6** — CIDR
inspection, address ranges, netmask/wildcard conversion, equal subnet
splitting, VLSM allocation, containment checks, set operations such as
merging, excluding, and diffing address space, and persistent subnet plans
with best-fit allocation and exports.

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
  Position        host #11 of 256
  Network         192.168.1.0
  Netmask         255.255.255.0  /24
  Wildcard        0.0.0.255
  Host range      192.168.1.1 – 192.168.1.254
  Broadcast       192.168.1.255
  Usable hosts    254 usable  ·  2^8 total
  Class           C
  Scope           Private
  Reverse DNS     10.1.168.192.in-addr.arpa
  Numeric         3232235786  0xc0a8010a
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

Every inspection also reports the typed address's reverse DNS name
(`in-addr.arpa` or `ip6.arpa`), integer and hexadecimal forms, and its position
inside the block (`host #N of M`). IPv6 output additionally includes compressed
and expanded forms plus a modified EUI-64 interface-ID hint.

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

Allocation options:

| Flag | Effect |
| --- | --- |
| `--classic` | Classic IPv4 subnetting: one- and two-host subnets use `/30`; never `/31` or `/32` |
| `--gateway` | Reserve one extra address per subnet for a gateway |
| `--growth PERCENT` | Inflate every host requirement by `PERCENT` before sizing |

```bash
$ subnetkit vlsm 10.0.0.0/24 --gateway --growth 25 LAN:100 WAN:2
$ subnetkit vlsm 192.168.1.0/24 --classic Printer:2 Link:1
```

Growth is applied first, then the gateway reservation. The `Needs` column shows
the requested count and, when they differ, the effective count used for sizing
(for example `100 → 125`).

### Plan address space

A plan is a small JSON document that keeps a parent network and the subnets
allocated inside it:

```json
{
  "parent": "10.0.0.0/16",
  "subnets": [
    {"name": "LAN", "cidr": "10.0.0.0/25", "vlan": 10, "notes": ""},
    {"name": "WAN", "cidr": "10.0.0.128/31", "vlan": 99, "notes": ""}
  ]
}
```

Create a plan, add subnets one at a time, and inspect the remaining space:

```bash
$ subnetkit plan init office.json 10.0.0.0/16
$ subnetkit plan add office.json LAN 100 --vlan 10
$ subnetkit plan add office.json WAN 2 --vlan 99
$ subnetkit plan add office.json Guest 20 --vlan 20

$ subnetkit plan show office.json
  10.0.0.0/16  plan · 3 subnets
  ────────────────────────────────────────────────────────────
  Name   CIDR           VLAN  Notes
  ─────  ─────────────  ────  ─────
  LAN    10.0.0.0/25      10
  WAN    10.0.0.128/31    99
  Guest  10.0.0.160/27    20

  Free space
    10.0.0.130/31
    10.0.0.132/30
    …
```

`plan add` uses **best-fit** allocation: it picks the smallest free block that
can hold the requested subnet, then carves the first child out of that block.
`--classic` and `--gateway` work the same way as in the VLSM command. Adding a
subnet validates the plan first, so an existing overlap, outside-parent block,
or duplicate name/VLAN must be fixed before more space is allocated.

```bash
$ subnetkit plan free office.json
$ subnetkit plan validate office.json
$ subnetkit plan export office.json --format json
$ subnetkit plan export office.json --format csv
$ subnetkit plan export office.json --format cisco
$ subnetkit plan export office.json --format iproute2
$ subnetkit plan export office.json --format terraform
```

`plan validate` reports `overlap`, `outside-parent`, `duplicate-name`,
`duplicate-vlan`, `invalid-cidr`, and `invalid-parent` errors. It exits `0`
when the plan is valid and `1` when issues were found, which makes it usable
in scripts. The `init`, `add`, `free`, `validate`, and `show` subcommands
accept `--json`; `export` always writes the selected format.

Export formats:

| Format | Output |
| --- | --- |
| `json` | The plan itself, with the `parent` and `subnets` schema |
| `csv` | `name,cidr,vlan,notes` rows |
| `cisco` | IOS VLAN/SVI configuration using the first host as the interface address |
| `iproute2` | `ip route add` / `ip -6 route add` commands |
| `terraform` | A `locals` block mapping each subnet name to `cidr_block`, `vlan`, and `notes` |

`plan init` refuses to overwrite an existing file; use `--force` when you
really mean to replace it. The file is always pretty-printed JSON with a
trailing newline.

### Merge, exclude, and diff

```bash
$ subnetkit merge 10.0.0.0/25 10.0.0.128/25 10.0.0.7
$ subnetkit exclude 10.0.0.0/24 10.0.0.64/26 10.0.0.200-10.0.0.220
$ subnetkit diff 10.0.0.0/24 10.0.0.0/25
```

- **merge** accepts CIDRs, individual hosts, and ranges, then returns the
  smallest CIDR set that covers all of them.
- **exclude** removes any CIDRs, hosts, or ranges from a base network and
  returns the remaining address space as minimal CIDR blocks.
- **diff** reports addresses only in A, only in B, and in both. The three
  sections are always present, even when empty.

Bare addresses in these commands mean a single host (`/32` or `/128`), not a
classful network. Mixed IPv4/IPv6 inputs are rejected for `merge` and `diff`;
`exclude` ignores exclusions from the other IP version and notes them.

### Check containment and overlap

```bash
$ subnetkit check 10.0.0.0/8 10.1.2.3 192.168.0.0/16
$ subnetkit check 10.0.0.0/8 "10.0.0.1 - 10.0.0.50"
```

Classifies each value as `inside`, `outside`, `subnet`, `supernet`,
`disjoint`, or `different-version`. Ranges are expanded into their minimal CIDR
list and compared block by block; fully contained ranges report `inside`,
partially contained ranges report `overlap`.

### JSON output

Every command accepts `--json`:

```bash
subnetkit split 10.0.0.0/16 -p 24 --json
subnetkit mask /26 --json
subnetkit merge 10.0.0.0/25 10.0.0.128/25 --json
subnetkit diff 10.0.0.0/24 10.0.0.0/25 --json
subnetkit plan show office.json --json
subnetkit plan validate office.json --json
subnetkit --json 192.168.1.10/24
```

## Shell completions

Install the optional completion extra and register the command with
`argcomplete`:

```bash
python -m pip install "subnetkit[completions]"
# bash (and shells with bash completion compatibility)
eval "$(register-python-argcomplete subnetkit)"
```

`argcomplete` completes subcommands, options, export formats, and filenames.
The CLI still works normally when `argcomplete` is not installed.

## Web UI

```bash
subnetkit web --host 127.0.0.1 --port 8765
```

Tabs for **Inspect**, **Split**, **Masks**, **VLSM**, **Check**, and
**Planner**, with live results, copy buttons, binary network/host bit
visualisation, and a responsive layout. The VLSM tab exposes the classic,
gateway, and growth controls. The Planner tab keeps an in-memory plan, adds
best-fit subnets, validates, shows free space, and previews every export
format. The server binds to `127.0.0.1` by default and makes no external
requests.

VLSM and Planner results include an address-space bar and a block grid. Hover
or focus any block to see its CIDR, allocation name, usable addresses, waste,
and free-space details. Every result also updates the URL hash, so the current
calculator inputs or plan can be copied and shared; opening that URL restores
the result. The moon/sun button switches between the dark and light themes and
remembers the choice in `localStorage`. Result tables can be downloaded as CSV
or JSON directly from the UI. All controls are keyboard accessible, and the
page keeps a strict Content Security Policy with no inline scripts, inline
styles, or external assets.

The local JSON API accepts `POST` requests with
`Content-Type: application/json`:

| Route | Payload |
| --- | --- |
| `/api/inspect` | `{"input": "192.168.1.10/24"}` |
| `/api/split` | `{"target": "10.0.0.0/16", "count": 4}` or `{"prefix": 24}` |
| `/api/summarize` | `{"start": "10.0.0.5", "end": "10.0.0.42"}` |
| `/api/mask` | `{"mask": "255.255.255.192"}` |
| `/api/vlsm` | `{"target": "10.0.0.0/24", "requirements": [...], "classic": true, "gateway": true, "growth": 25}` |
| `/api/check` | `{"target": "10.0.0.0/8", "others": ["10.1.2.3", "10.0.0.1 - 10.0.0.50"]}` |
| `/api/merge` | `{"inputs": ["10.0.0.0/25", "10.0.0.128/25"]}` |
| `/api/exclude` | `{"base": "10.0.0.0/24", "exclude": ["10.0.0.64/26"]}` |
| `/api/diff` | `{"a": "10.0.0.0/24", "b": "10.0.0.0/25"}` |
| `/api/plan/init` | `{"parent": "10.0.0.0/16"}` |
| `/api/plan/add` | `{"plan": {...}, "name": "LAN", "hosts": 100, "vlan": 10}` |
| `/api/plan/free` | `{"plan": {...}}` |
| `/api/plan/validate` | `{"plan": {...}}` |
| `/api/plan/show` | `{"plan": {...}}` |
| `/api/plan/export` | `{"plan": {...}, "format": "csv"}` |

`/api/plan` is also available as a dispatcher:
`{"action": "add", "plan": {...}, ...}`. The web API works with plan objects
in memory; unlike the CLI it never accepts or writes filesystem paths.

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
- **Set operations** treat bare addresses as single hosts. `merge` and `diff`
  reject mixed IP versions; `exclude` ignores non-overlapping and
  different-version inputs with notes.
- **VLSM growth** is a non-negative percentage. The effective requirement is
  `ceil(hosts × (1 + growth / 100))`, plus one address when `--gateway` is set.
- **Classic VLSM** applies to IPv4 only. One- and two-host subnets receive a
  `/30`; IPv6 keeps its normal host-sized prefixes.
- **Plan allocation** is best-fit: the smallest free CIDR that fits is chosen,
  and its first child becomes the new subnet. Existing plan entries are kept in
  insertion order; free space is recomputed from the parent and all entries.
- **Plan validation** treats duplicate names and duplicate non-null VLANs as
  errors, rejects CIDRs outside the parent (including mixed IP versions), and
  reports every overlapping pair. `plan validate` exits `1` when invalid.
- **Plan exports** do not validate first; run `plan validate` before exporting
  if the file may have been edited by hand.
- **Split limit** is 4,096 generated subnets to keep terminal and browser
  output sensible.

## Development

Install the development tools, then run the tests and checks:

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
ruff check .
mypy .
```

The test suite includes Hypothesis property tests for VLSM allocation
invariants and split/merge round trips. CI runs `unittest` on Python 3.9
through 3.13, and runs Ruff plus Mypy on Python 3.13. Pushing a `v*` tag
builds source and wheel distributions and publishes them to PyPI through
Trusted Publishing.

Layout:

```
subnetkit/
  core.py            all calculations (stdlib ipaddress only)
  plan.py            persistent JSON plans and export formats
  cli.py             argparse CLI, terminal rendering, completions
  web.py             local HTTP server and JSON API
  py.typed           PEP 561 marker
  static/            index.html, styles.css, app.js
tests/test_core.py       unit tests for every calculator
tests/test_plan.py       plan allocation, validation, and export tests
tests/test_cli.py        CLI and JSON output tests
tests/test_web.py        HTTP integration tests for the local API
tests/test_properties.py Hypothesis allocation and split/merge properties
bin/subnetkit            run-from-checkout wrapper
```

The core package has no required runtime dependencies; `argcomplete` is only
needed for the optional shell-completion extra. Python 3.9+.
