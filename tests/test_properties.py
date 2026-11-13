"""Property-based tests for allocator and split/merge invariants."""

import ipaddress
import unittest

from hypothesis import given, settings
from hypothesis import strategies as st

from subnetkit import core

PROPERTY_SETTINGS = settings(max_examples=100, deadline=None)


def _requirements(host_counts):
    return [
        (f"subnet-{index}", hosts)
        for index, hosts in enumerate(host_counts, 1)
    ]


def _assert_allocations_disjoint(test, allocations):
    for index, left in enumerate(allocations):
        for right in allocations[index + 1 :]:
            test.assertFalse(
                left.overlaps(right),
                f"{left} overlaps {right}",
            )


class VlsmPropertyTests(unittest.TestCase):
    @given(
        st.integers(min_value=0, max_value=2**32 - 1),
        st.integers(min_value=8, max_value=16),
        st.lists(
            st.integers(min_value=1, max_value=512),
            min_size=1,
            max_size=8,
        ),
    )
    @PROPERTY_SETTINGS
    def test_ipv4_allocations_stay_inside_parent_and_do_not_overlap(
        self, address, prefix, host_counts
    ):
        parent = ipaddress.IPv4Network(
            f"{ipaddress.IPv4Address(address)}/{prefix}",
            strict=False,
        )
        result = core.vlsm(str(parent), _requirements(host_counts))
        allocations = [
            ipaddress.IPv4Network(item["cidr"])
            for item in result["allocations"]
        ]

        self.assertEqual(len(allocations), len(host_counts))
        for allocation in allocations:
            self.assertTrue(allocation.subnet_of(parent))
        _assert_allocations_disjoint(self, allocations)

    @given(
        st.integers(min_value=0, max_value=2**128 - 1),
        st.integers(min_value=96, max_value=112),
        st.lists(
            st.integers(min_value=1, max_value=512),
            min_size=1,
            max_size=8,
        ),
    )
    @PROPERTY_SETTINGS
    def test_ipv6_allocations_stay_inside_parent_and_do_not_overlap(
        self, address, prefix, host_counts
    ):
        parent = ipaddress.IPv6Network(
            f"{ipaddress.IPv6Address(address)}/{prefix}",
            strict=False,
        )
        result = core.vlsm(str(parent), _requirements(host_counts))
        allocations = [
            ipaddress.IPv6Network(item["cidr"])
            for item in result["allocations"]
        ]

        self.assertEqual(len(allocations), len(host_counts))
        for allocation in allocations:
            self.assertTrue(allocation.subnet_of(parent))
        _assert_allocations_disjoint(self, allocations)


class SplitMergePropertyTests(unittest.TestCase):
    @given(
        st.integers(min_value=0, max_value=2**32 - 1),
        st.integers(min_value=8, max_value=25),
        st.integers(min_value=1, max_value=6),
    )
    @PROPERTY_SETTINGS
    def test_ipv4_split_then_collapse_equals_parent(
        self, address, prefix, extra_prefix_bits
    ):
        parent = ipaddress.ip_network(
            f"{ipaddress.IPv4Address(address)}/{prefix}",
            strict=False,
        )
        new_prefix = prefix + extra_prefix_bits
        result = core.split_network(str(parent), prefix=new_prefix)
        collapsed = core.merge(
            [subnet["cidr"] for subnet in result["subnets"]]
        )

        self.assertEqual(collapsed["cidr_list"], [str(parent)])

    @given(
        st.integers(min_value=0, max_value=2**32 - 1),
        st.integers(min_value=8, max_value=24),
        st.integers(min_value=1, max_value=64),
    )
    @PROPERTY_SETTINGS
    def test_ipv4_split_by_count_then_collapse_equals_parent(
        self, address, prefix, count
    ):
        parent = ipaddress.ip_network(
            f"{ipaddress.IPv4Address(address)}/{prefix}",
            strict=False,
        )
        result = core.split_network(str(parent), count=count)
        collapsed = core.merge(
            [subnet["cidr"] for subnet in result["subnets"]]
        )

        self.assertEqual(collapsed["cidr_list"], [str(parent)])

    @given(
        st.integers(min_value=0, max_value=2**128 - 1),
        st.integers(min_value=96, max_value=121),
        st.integers(min_value=1, max_value=6),
    )
    @PROPERTY_SETTINGS
    def test_ipv6_split_then_collapse_equals_parent(
        self, address, prefix, extra_prefix_bits
    ):
        parent = ipaddress.ip_network(
            f"{ipaddress.IPv6Address(address)}/{prefix}",
            strict=False,
        )
        new_prefix = prefix + extra_prefix_bits
        result = core.split_network(str(parent), prefix=new_prefix)
        collapsed = core.merge(
            [subnet["cidr"] for subnet in result["subnets"]]
        )

        self.assertEqual(collapsed["cidr_list"], [str(parent)])


if __name__ == "__main__":
    unittest.main()
