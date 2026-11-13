"""subnetkit — an IP and subnet calculator.

Public API:
    describe(text)         CIDR, host, or IP range → detail dict
    split_network(cidr)    split into equal subnets
    summarize(start, end)  range → minimal CIDR list
    mask_info(mask)        prefix/netmask/wildcard conversion
    vlsm(parent, reqs)     variable-length subnet allocation
    check_relations(...)   containment and overlap checks

Persistent plan helpers live in :mod:`subnetkit.plan`.
"""

from . import plan  # noqa: F401
from .core import (  # noqa: F401
    InputError,
    check_relations,
    describe,
    describe_network,
    describe_range,
    mask_info,
    split_network,
    summarize,
    vlsm,
)

__version__ = "1.0.0"
