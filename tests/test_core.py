import ast
import ipaddress
import json
import pathlib
import unittest

from subnetkit import __version__ as package_version
from subnetkit import cli, core


class DescribeTests(unittest.TestCase):
    def test_ipv4_cidr(self):
        data = core.describe("192.168.1.10/24")
        self.assertEqual(data["cidr"], "192.168.1.0/24")
        self.assertEqual(data["network_address"], "192.168.1.0")
        self.assertEqual(data["address"], "192.168.1.10")
        self.assertEqual(data["broadcast"], "192.168.1.255")
        self.assertEqual(data["netmask"], "255.255.255.0")
        self.assertEqual(data["wildcard"], "0.0.0.255")
        self.assertEqual(data["first_host"], "192.168.1.1")
        self.assertEqual(data["last_host"], "192.168.1.254")
        self.assertEqual(data["usable_hosts"], 254)
        self.assertEqual(data["total_addresses"], 256)
        self.assertEqual(data["class"], "C")
        self.assertEqual(data["scope"], "Private")
        self.assertFalse(data["input_is_host"])
        self.assertEqual(data["host_offset"], 10)
        self.assertTrue(any("Host bits" in note for note in data["notes"]))
        self.assertEqual(data["binary"]["width"], 32)
        json.dumps(data)

    def test_bare_ipv4_uses_classful_default(self):
        data = core.describe("192.168.1.10")
        self.assertTrue(data["input_is_host"])
        self.assertEqual(data["prefix"], 24)
        self.assertEqual(data["cidr"], "192.168.1.0/24")
        self.assertTrue(any("assumed" in note for note in data["notes"]))

        self.assertEqual(core.describe("10.1.2.3")["prefix"], 8)
        self.assertEqual(core.describe("172.20.1.1")["prefix"], 16)

    def test_dotted_mask_pair(self):
        data = core.describe("172.16.5.4 255.255.240.0")
        self.assertEqual(data["cidr"], "172.16.0.0/20")
        self.assertEqual(data["prefix"], 20)

    def test_point_to_point_and_host_routes(self):
        point = core.describe("10.0.0.0/31")
        self.assertEqual(point["usable_hosts"], 2)
        self.assertEqual(point["first_host"], "10.0.0.0")
        self.assertEqual(point["last_host"], "10.0.0.1")
        self.assertTrue(any("RFC 3021" in note for note in point["notes"]))

        host = core.describe("10.0.0.7/32")
        self.assertEqual(host["usable_hosts"], 1)
        self.assertEqual(host["first_host"], "10.0.0.7")
        self.assertEqual(host["last_host"], "10.0.0.7")

    def test_ipv6(self):
        data = core.describe("2001:db8::1/64")
        self.assertEqual(data["version"], 6)
        self.assertEqual(data["cidr"], "2001:db8::/64")
        self.assertEqual(data["network_address"], "2001:db8::")
        self.assertEqual(data["first_host"], "2001:db8::")
        self.assertEqual(data["last_host"], "2001:db8::ffff:ffff:ffff:ffff")
        self.assertIsNone(data["broadcast"])
        self.assertEqual(data["total_addresses"], 2**64)
        self.assertEqual(data["usable_hosts"], 2**64)
        self.assertIsNone(data["class"])
        self.assertEqual(data["total_power"], "2^64")

    def test_invalid_input(self):
        for bad in ("300.1.1.1", "192.168.1.1/33", "hello", ""):
            with self.subTest(bad=bad), self.assertRaises(core.InputError):
                core.describe(bad)

    def test_ipv6_host_scope_uses_typed_address(self):
        loopback = core.describe("::1")
        self.assertEqual(loopback["scope"], "Loopback")
        self.assertEqual(loopback["flags"], ["Loopback"])
        self.assertNotIn("Global", loopback["flags"])
        self.assertFalse(loopback["is_global"])

        mapped = core.describe("::ffff:1.2.3.4")
        self.assertEqual(mapped["scope"], "IPv4-mapped")
        self.assertEqual(mapped["flags"], ["IPv4-mapped"])

        # Explicit host-sized blocks are classified by the whole block too.
        self.assertEqual(core.describe("::1/128")["scope"], "Loopback")
        self.assertEqual(
            core.describe("::ffff:1.2.3.4/128")["scope"], "IPv4-mapped"
        )

    def test_supernet_scope_spans_ranges(self):
        for cidr in ("10.0.0.0/7", "192.168.0.0/15", "0.0.0.0/0"):
            with self.subTest(cidr=cidr):
                data = core.describe(cidr)
                self.assertEqual(data["scope"], "Spans multiple ranges")
                self.assertEqual(data["flags"], [])
                self.assertFalse(data["is_private"])
                self.assertFalse(data["is_global"])

        private = core.describe("10.0.0.0/8")
        self.assertEqual(private["scope"], "Private")
        self.assertEqual(private["flags"], ["Private"])

    def test_info_extras_ipv4(self):
        data = core.describe("192.168.1.10/24")
        self.assertEqual(data["reverse_dns"], "10.1.168.192.in-addr.arpa")
        self.assertEqual(data["integer"], 3232235786)
        self.assertEqual(data["decimal"], 3232235786)
        self.assertEqual(data["hex"], "0xc0a8010a")
        self.assertEqual(data["hex_padded"], "0xc0a8010a")
        self.assertEqual(data["host_number"], 11)
        self.assertEqual(data["host_total"], 256)
        self.assertEqual(data["host_position"], "host #11 of 256")
        self.assertIsNone(data["ipv6_compressed"])
        self.assertIsNone(data["ipv6_expanded"])
        self.assertIsNone(data["eui64"])
        self.assertIsNone(data["eui64_hint"])

        host = core.describe("10.0.0.7/32")
        self.assertEqual(host["host_number"], 1)
        self.assertEqual(host["host_total"], 1)
        self.assertEqual(host["host_position"], "host #1 of 1")

        everything = core.describe("0.0.0.0/0")
        self.assertEqual(everything["host_number"], 1)
        self.assertEqual(everything["host_total"], 2**32)

    def test_info_extras_ipv6(self):
        data = core.describe("2001:db8::1/64")
        self.assertEqual(data["ipv6_compressed"], "2001:db8::1")
        self.assertEqual(
            data["ipv6_expanded"],
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        )
        self.assertEqual(data["eui64"], "0000:0000:0000:0001")
        self.assertIn("fe80::", data["eui64_hint"])
        self.assertIn("U/L bit", data["eui64_hint"])
        self.assertTrue(data["reverse_dns"].endswith(".ip6.arpa"))
        self.assertTrue(
            data["reverse_dns"].startswith(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
            )
        )
        self.assertEqual(
            data["integer"], int(ipaddress.ip_address("2001:db8::1"))
        )
        self.assertEqual(data["host_total"], 2**64)

    def test_whitespace_around_prefix(self):
        for text in (
            "192.168.1.10 /24",
            "192.168.1.10/ 24",
            "192.168.1.10 / 24",
        ):
            with self.subTest(text=text):
                data = core.describe(text)
                self.assertEqual(data["cidr"], "192.168.1.0/24")
                self.assertEqual(data["address"], "192.168.1.10")

        masked = core.describe("172.16.5.4 / 255.255.240.0")
        self.assertEqual(masked["cidr"], "172.16.0.0/20")

    def test_specific_parse_errors(self):
        cases = (
            ("192.168.1.1/33", r"Prefix /33 is invalid for IPv4, max is /32"),
            ("2001:db8::1/129", r"Prefix /129 is invalid for IPv6, max is /128"),
            ("192.168.1.1/", r"Missing prefix after '/'"),
            ("192.168.01.1", r"leading zeros"),
            ("fe80::1%eth0/64", r"zone IDs are not supported"),
        )
        for text, pattern in cases:
            with self.subTest(text=text), self.assertRaisesRegex(
                core.InputError, pattern
            ):
                core.describe(text)


class RangeTests(unittest.TestCase):
    def test_range_to_cidrs(self):
        data = core.describe("192.168.1.5 - 192.168.1.10")
        self.assertEqual(data["kind"], "range")
        self.assertEqual(data["total_addresses"], 6)
        self.assertEqual(
            data["cidr_list"],
            [
                "192.168.1.5/32",
                "192.168.1.6/31",
                "192.168.1.8/31",
                "192.168.1.10/32",
            ],
        )
        self.assertEqual(data["cidr_count"], 4)
        self.assertEqual(data["common_prefix"], "192.168.1.0/28")
        self.assertEqual(data["scope"], "Private")

    def test_range_reversed(self):
        data = core.describe("10.0.0.42 - 10.0.0.5")
        self.assertEqual(data["start"], "10.0.0.5")
        self.assertEqual(data["end"], "10.0.0.42")
        self.assertTrue(any("reversed" in note for note in data["notes"]))

    def test_single_address_range(self):
        data = core.describe("10.0.0.9 - 10.0.0.9")
        self.assertEqual(data["cidr_list"], ["10.0.0.9/32"])
        self.assertTrue(any("exactly one" in note for note in data["notes"]))

    def test_whole_network_is_one_block(self):
        data = core.summarize("192.168.1.0", "192.168.1.255")
        self.assertEqual(data["cidr_list"], ["192.168.1.0/24"])

    def test_ipv6_range(self):
        data = core.describe("2001:db8::1 - 2001:db8::3")
        self.assertEqual(data["cidr_list"], ["2001:db8::1/128", "2001:db8::2/127"])
        self.assertEqual(data["total_addresses"], 3)

    def test_summarize_requires_end(self):
        with self.assertRaises(core.InputError):
            core.summarize("192.168.1.5")


class MergeTests(unittest.TestCase):
    def test_adjacent_and_overlapping_inputs(self):
        data = core.merge(["10.0.0.0/25", "10.0.0.128/25"])
        self.assertEqual(data["kind"], "merge")
        self.assertEqual(data["version"], 4)
        self.assertEqual(data["cidr_list"], ["10.0.0.0/24"])
        self.assertEqual(data["cidr_count"], 1)
        self.assertEqual(data["total_addresses"], 256)

        overlapping = core.merge(
            ["10.0.0.1 - 10.0.0.10", "10.0.0.0/28"]
        )
        self.assertEqual(overlapping["cidr_list"], ["10.0.0.0/28"])

    def test_hosts_ranges_and_ipv6(self):
        hosts = core.merge(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(
            hosts["cidr_list"], ["10.0.0.1/32", "10.0.0.2/31"]
        )

        ipv6 = core.merge(["2001:db8::/127", "2001:db8::2/127"])
        self.assertEqual(ipv6["version"], 6)
        self.assertEqual(ipv6["cidr_list"], ["2001:db8::/126"])

    def test_edge_prefixes_and_empty(self):
        self.assertEqual(
            core.merge(["0.0.0.0/1", "128.0.0.0/1"])["cidr_list"],
            ["0.0.0.0/0"],
        )
        self.assertEqual(
            core.merge(["10.0.0.0/31", "10.0.0.2/32"])["cidr_list"],
            ["10.0.0.0/31", "10.0.0.2/32"],
        )

        empty = core.merge([])
        self.assertIsNone(empty["version"])
        self.assertEqual(empty["cidr_list"], [])
        self.assertEqual(empty["total_addresses"], 0)
        self.assertTrue(empty["notes"])

    def test_mixed_versions_rejected(self):
        with self.assertRaisesRegex(core.InputError, "IPv4 and IPv6"):
            core.merge(["10.0.0.0/8", "2001:db8::/32"])


class ExcludeTests(unittest.TestCase):
    def test_carve_out_middle(self):
        data = core.exclude("10.0.0.0/24", ["10.0.0.64/26"])
        self.assertEqual(data["kind"], "exclude")
        self.assertEqual(
            data["cidr_list"], ["10.0.0.0/26", "10.0.0.128/25"]
        )
        self.assertEqual(data["total_addresses"], 192)
        self.assertEqual(data["removed_addresses"], 64)

    def test_exclude_all_and_outside(self):
        all_gone = core.exclude("10.0.0.0/24", ["10.0.0.0/24"])
        self.assertEqual(all_gone["cidr_list"], [])
        self.assertEqual(all_gone["total_addresses"], 0)
        self.assertEqual(all_gone["removed_addresses"], 256)

        outside = core.exclude("10.0.0.0/24", ["192.168.0.0/16"])
        self.assertEqual(outside["cidr_list"], ["10.0.0.0/24"])
        self.assertEqual(outside["total_addresses"], 256)
        self.assertTrue(any("Ignored" in note for note in outside["notes"]))

    def test_ranges_ipv6_and_version_mismatch(self):
        ranged = core.exclude("10.0.0.0/24", ["10.0.0.1 - 10.0.0.3"])
        self.assertEqual(ranged["total_addresses"], 253)

        ipv6 = core.exclude("2001:db8::/126", ["2001:db8::/127"])
        self.assertEqual(ipv6["cidr_list"], ["2001:db8::2/127"])

        mismatch = core.exclude("10.0.0.0/24", ["2001:db8::/64"])
        self.assertEqual(mismatch["cidr_list"], ["10.0.0.0/24"])
        self.assertTrue(any("different IP version" in note for note in mismatch["notes"]))

    def test_edge_prefixes_and_empty(self):
        self.assertEqual(
            core.exclude("10.0.0.0/31", ["10.0.0.0/32"])["cidr_list"],
            ["10.0.0.1/32"],
        )
        self.assertEqual(
            core.exclude("10.0.0.1/32", ["10.0.0.1/32"])["cidr_list"],
            [],
        )

        full = core.exclude("0.0.0.0/0", ["10.0.0.0/8"])
        self.assertEqual(full["total_addresses"], 2**32 - 2**24)
        self.assertGreater(full["cidr_count"], 0)

        unchanged = core.exclude("10.0.0.0/24", [])
        self.assertEqual(unchanged["cidr_list"], ["10.0.0.0/24"])
        self.assertTrue(unchanged["notes"])


class DiffTests(unittest.TestCase):
    def test_overlap_partial_and_disjoint(self):
        data = core.diff("10.0.0.0/24", "10.0.0.0/25")
        self.assertEqual(data["only_a"], ["10.0.0.128/25"])
        self.assertEqual(data["only_b"], [])
        self.assertEqual(data["both"], ["10.0.0.0/25"])
        self.assertEqual(data["only_a_addresses"], 128)
        self.assertEqual(data["both_addresses"], 128)

        disjoint = core.diff("10.0.0.0/24", "10.0.1.0/24")
        self.assertEqual(disjoint["only_a"], ["10.0.0.0/24"])
        self.assertEqual(disjoint["only_b"], ["10.0.1.0/24"])
        self.assertEqual(disjoint["both"], [])
        self.assertTrue(any("do not overlap" in note for note in disjoint["notes"]))

    def test_identical_and_empty(self):
        same = core.diff("10.0.0.0/24", "10.0.0.0/24")
        self.assertEqual(same["only_a"], [])
        self.assertEqual(same["only_b"], [])
        self.assertEqual(same["both"], ["10.0.0.0/24"])
        self.assertTrue(any("same addresses" in note for note in same["notes"]))

        one_side = core.diff("", "10.0.0.0/24")
        self.assertEqual(one_side["version"], 4)
        self.assertEqual(one_side["only_a"], [])
        self.assertEqual(one_side["only_b"], ["10.0.0.0/24"])
        self.assertEqual(one_side["both"], [])

        empty = core.diff("", "")
        self.assertIsNone(empty["version"])
        self.assertEqual(empty["only_a"], [])
        self.assertEqual(empty["only_b"], [])
        self.assertEqual(empty["both"], [])
        self.assertTrue(empty["notes"])

    def test_ipv6_prefix_edges_and_versions(self):
        ipv6 = core.diff("2001:db8::/126", "2001:db8::/127")
        self.assertEqual(ipv6["only_a"], ["2001:db8::2/127"])
        self.assertEqual(ipv6["both"], ["2001:db8::/127"])

        full = core.diff("0.0.0.0/0", "0.0.0.0/1")
        self.assertEqual(full["only_a"], ["128.0.0.0/1"])
        self.assertEqual(full["both"], ["0.0.0.0/1"])

        points = core.diff("10.0.0.0/31", "10.0.0.1/32")
        self.assertEqual(points["only_a"], ["10.0.0.0/32"])
        self.assertEqual(points["both"], ["10.0.0.1/32"])

        with self.assertRaisesRegex(core.InputError, "IPv4 and IPv6"):
            core.diff("10.0.0.0/8", "2001:db8::/32")


class MaskTests(unittest.TestCase):
    def test_dotted_mask(self):
        data = core.mask_info("255.255.255.192")
        self.assertEqual(data["prefix"], 26)
        self.assertEqual(data["netmask"], "255.255.255.192")
        self.assertEqual(data["wildcard"], "0.0.0.63")
        self.assertEqual(data["total_addresses"], 64)
        self.assertEqual(data["usable_hosts"], 62)
        self.assertEqual(data["input_kind"], "netmask")

    def test_prefix_forms(self):
        self.assertEqual(core.mask_info("/26")["prefix"], 26)
        self.assertEqual(core.mask_info("26")["prefix"], 26)
        self.assertEqual(core.mask_info("64", 6)["prefix"], 64)

    def test_wildcard_input(self):
        data = core.mask_info("0.0.0.255")
        self.assertEqual(data["prefix"], 24)
        self.assertEqual(data["input_kind"], "wildcard")
        self.assertEqual(data["netmask"], "255.255.255.0")
        self.assertTrue(any("wildcard" in note for note in data["notes"]))

    def test_zero_and_full_masks(self):
        zero = core.mask_info("0.0.0.0")
        self.assertEqual(zero["prefix"], 0)
        self.assertEqual(zero["usable_hosts"], 2**32 - 2)
        full = core.mask_info("255.255.255.255")
        self.assertEqual(full["prefix"], 32)
        self.assertEqual(full["usable_hosts"], 1)

    def test_ipv6_mask(self):
        data = core.mask_info("ffff:ffff:ffff:ffff::")
        self.assertEqual(data["version"], 6)
        self.assertEqual(data["prefix"], 64)
        self.assertEqual(data["total_addresses"], 2**64)

    def test_non_contiguous_mask(self):
        with self.assertRaises(core.InputError):
            core.mask_info("255.0.255.0")

    def test_out_of_range_prefix(self):
        with self.assertRaises(core.InputError):
            core.mask_info("33")


class SplitTests(unittest.TestCase):
    def test_split_by_count(self):
        data = core.split_network("192.168.1.0/24", count=4)
        self.assertEqual(data["new_prefix"], 26)
        self.assertEqual(data["generated_count"], 4)
        self.assertEqual(data["subnets"][0]["cidr"], "192.168.1.0/26")
        self.assertEqual(data["subnets"][-1]["cidr"], "192.168.1.192/26")
        self.assertEqual(data["subnets"][0]["usable_hosts"], 62)

    def test_non_power_of_two_count(self):
        data = core.split_network("192.168.1.0/24", count=3)
        self.assertEqual(data["new_prefix"], 26)
        self.assertEqual(data["generated_count"], 4)
        self.assertTrue(any("next power of two" in note for note in data["notes"]))

    def test_split_by_prefix(self):
        data = core.split_network("10.0.0.0/16", prefix=24)
        self.assertEqual(data["generated_count"], 256)
        self.assertEqual(data["subnets"][1]["cidr"], "10.0.1.0/24")

    def test_invalid_splits(self):
        with self.assertRaises(core.InputError):
            core.split_network("10.0.0.0/24", prefix=16)
        with self.assertRaises(core.InputError):
            core.split_network("10.0.0.0/24", count=0)
        with self.assertRaises(core.InputError):
            core.split_network("10.0.0.0/24")

    def test_split_cap(self):
        with self.assertRaises(core.InputError):
            core.split_network("10.0.0.0/8", count=65536)
        with self.assertRaises(core.InputError):
            core.split_network("2001:db8::/64", prefix=100)

    def test_ipv6_split(self):
        data = core.split_network("2001:db8::/64", count=4)
        self.assertEqual(data["generated_count"], 4)
        self.assertEqual(data["subnets"][0]["cidr"], "2001:db8::/66")
        self.assertEqual(data["subnets"][0]["broadcast"], None)


class VlsmTests(unittest.TestCase):
    def test_allocation(self):
        data = core.vlsm(
            "192.168.1.0/24",
            [{"name": "LAN", "hosts": 100}, {"name": "WAN", "hosts": 2}, {"name": "Guest", "hosts": 20}],
        )
        by_name = {item["name"]: item for item in data["allocations"]}
        self.assertEqual(by_name["LAN"]["cidr"], "192.168.1.0/25")
        self.assertEqual(by_name["Guest"]["cidr"], "192.168.1.128/27")
        self.assertEqual(by_name["WAN"]["cidr"], "192.168.1.160/31")
        self.assertEqual(by_name["WAN"]["usable_hosts"], 2)
        self.assertEqual(by_name["WAN"]["waste"], 0)

        networks = [ipaddress.ip_network(item["cidr"]) for item in data["allocations"]]
        for left in networks:
            for right in networks:
                if left is not right:
                    self.assertFalse(left.overlaps(right))

        allocated = sum(net.num_addresses for net in networks)
        self.assertEqual(allocated + data["free_addresses"], 256)
        self.assertEqual(
            data["free_blocks"],
            [
                "192.168.1.162/31",
                "192.168.1.164/30",
                "192.168.1.168/29",
                "192.168.1.176/28",
                "192.168.1.192/26",
            ],
        )

    def test_not_enough_space(self):
        with self.assertRaises(core.InputError) as ctx:
            core.vlsm("10.0.0.0/30", [{"name": "too-big", "hosts": 10}])
        message = str(ctx.exception)
        self.assertIn("largest free block is 10.0.0.0/30", message)
        self.assertIn("short 12 addresses", message)

    def test_not_enough_space_reports_shortfall(self):
        with self.assertRaises(core.InputError) as ctx:
            core.vlsm(
                "10.0.0.0/24",
                [
                    {"name": "A", "hosts": 100},
                    {"name": "B", "hosts": 100},
                    {"name": "C", "hosts": 100},
                ],
            )
        message = str(ctx.exception)
        self.assertIn("no free blocks remain", message)
        self.assertIn("largest free block is none", message)
        self.assertIn("short 128 addresses", message)

    def test_ipv6_allocation(self):
        data = core.vlsm("2001:db8::/64", [{"name": "A", "hosts": 1000}, {"name": "B", "hosts": 10}])
        self.assertEqual(data["version"], 6)
        self.assertEqual(len(data["allocations"]), 2)
        self.assertEqual(data["allocations"][0]["prefix"], 118)

    def test_prefix_for_hosts(self):
        self.assertEqual(core.prefix_for_hosts(1), 32)
        self.assertEqual(core.prefix_for_hosts(2), 31)
        self.assertEqual(core.prefix_for_hosts(3), 29)
        self.assertEqual(core.prefix_for_hosts(100), 25)
        self.assertEqual(core.prefix_for_hosts(254), 24)
        self.assertEqual(core.prefix_for_hosts(1, 6), 128)
        self.assertEqual(core.prefix_for_hosts(100, 6), 121)

    def test_classic_mode(self):
        data = core.vlsm(
            "10.0.0.0/24",
            [{"name": "one", "hosts": 1}, {"name": "two", "hosts": 2}],
            classic=True,
        )
        by_name = {item["name"]: item for item in data["allocations"]}
        self.assertEqual(by_name["one"]["prefix"], 30)
        self.assertEqual(by_name["two"]["prefix"], 30)
        self.assertTrue(data["classic"])
        self.assertTrue(any("Classic mode" in note for note in data["notes"]))
        self.assertFalse(
            any(item["prefix"] in (31, 32) for item in data["allocations"])
        )

        self.assertEqual(core.prefix_for_hosts(1, classic=True), 30)
        self.assertEqual(core.prefix_for_hosts(2, classic=True), 30)
        self.assertEqual(core.prefix_for_hosts(3, classic=True), 29)
        self.assertEqual(core.prefix_for_hosts(1, 6, classic=True), 128)

    def test_gateway_mode(self):
        data = core.vlsm(
            "10.0.0.0/24",
            [{"name": "two", "hosts": 2}, {"name": "one", "hosts": 1}],
            gateway=True,
        )
        by_name = {item["name"]: item for item in data["allocations"]}
        self.assertEqual(by_name["two"]["effective_hosts"], 3)
        self.assertEqual(by_name["two"]["prefix"], 29)
        self.assertEqual(by_name["two"]["gateway_reserved"], 1)
        self.assertEqual(by_name["one"]["effective_hosts"], 2)
        self.assertEqual(by_name["one"]["prefix"], 31)
        self.assertTrue(data["gateway"])

        self.assertEqual(core.prefix_for_hosts(1, gateway=True), 31)
        self.assertEqual(core.prefix_for_hosts(2, gateway=True), 29)
        self.assertEqual(
            core.prefix_for_hosts(1, classic=True, gateway=True), 30
        )

    def test_growth_mode(self):
        data = core.vlsm(
            "10.0.0.0/24",
            [{"name": "LAN", "hosts": 10}],
            growth=20,
        )
        allocation = data["allocations"][0]
        self.assertEqual(allocation["requested_hosts"], 10)
        self.assertEqual(allocation["effective_hosts"], 12)
        self.assertEqual(allocation["prefix"], 28)
        self.assertEqual(data["growth_percent"], 20)
        self.assertTrue(any("inflated by 20%" in note for note in data["notes"]))

        combined = core.vlsm(
            "10.0.0.0/24",
            [{"name": "LAN", "hosts": 10}],
            growth=20,
            gateway=True,
        )["allocations"][0]
        self.assertEqual(combined["effective_hosts"], 13)
        self.assertEqual(combined["prefix"], 28)
        self.assertEqual(combined["waste"], 1)

        self.assertEqual(core.prefix_for_hosts(10, growth=20), 28)
        self.assertEqual(core.prefix_for_hosts(10, growth=0), 28)

    def test_invalid_growth(self):
        for growth in (-1, -0.5, float("nan"), float("inf")):
            with self.subTest(growth=growth):
                with self.assertRaises(core.InputError):
                    core.prefix_for_hosts(1, growth=growth)
                with self.assertRaises(core.InputError):
                    core.vlsm(
                        "10.0.0.0/24",
                        [{"name": "A", "hosts": 1}],
                        growth=growth,
                    )


class CheckTests(unittest.TestCase):
    def test_relations(self):
        data = core.check_relations(
            "10.0.0.0/8",
            ["10.1.2.3", "11.0.0.1", "10.10.0.0/16", "0.0.0.0/0", "192.168.0.0/16"],
        )
        relations = [item["relation"] for item in data["results"]]
        self.assertEqual(relations, ["inside", "outside", "subnet", "supernet", "disjoint"])
        self.assertTrue(data["any_contained"])
        self.assertTrue(data["any_overlap"])

    def test_invalid_and_version_mismatch(self):
        data = core.check_relations("10.0.0.0/8", ["not-an-ip", "2001:db8::/32"])
        self.assertEqual(data["results"][0]["relation"], "invalid")
        self.assertEqual(data["results"][1]["relation"], "different-version")

    def test_ranges_are_expanded_and_compared(self):
        inside = core.check_relations(
            "10.0.0.0/8", ["10.0.0.1 - 10.0.0.5"]
        )["results"][0]
        self.assertEqual(inside["type"], "range")
        self.assertEqual(inside["relation"], "inside")
        self.assertTrue(inside["contained"])
        self.assertEqual(inside["block_count"], len(inside["cidr_list"]))
        self.assertTrue(inside["cidr_list"])
        self.assertTrue(all(block["contained"] for block in inside["blocks"]))

        partial = core.check_relations(
            "10.0.0.0/24", ["10.0.0.200 - 10.0.1.10"]
        )["results"][0]
        self.assertEqual(partial["relation"], "overlap")
        self.assertFalse(partial["contained"])

        outside = core.check_relations(
            "10.0.0.0/8", ["192.168.0.1 - 192.168.0.5"]
        )["results"][0]
        self.assertEqual(outside["relation"], "outside")
        self.assertFalse(outside["contained"])

        ipv6 = core.check_relations(
            "2001:db8::/64", ["2001:db8::1 - 2001:db8::3"]
        )["results"][0]
        self.assertEqual(ipv6["relation"], "inside")

        mismatch = core.check_relations(
            "10.0.0.0/8", ["2001:db8::1 - 2001:db8::3"]
        )["results"][0]
        self.assertEqual(mismatch["relation"], "different-version")

        invalid = core.check_relations(
            "10.0.0.0/8", ["10.0.0.1 - 10.0.0.999"]
        )["results"][0]
        self.assertEqual(invalid["relation"], "invalid")


class VersionTests(unittest.TestCase):
    def test_single_version_source(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn(
            'version = {attr = "subnetkit.__version__"}', pyproject
        )

        self.assertEqual(package_version, "1.0.0")
        self.assertEqual(cli.__version__, package_version)

        tree = ast.parse(
            (root / "subnetkit" / "cli.py").read_text(encoding="utf-8")
        )
        assigned_names = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        self.assertNotIn("__version__", assigned_names)


if __name__ == "__main__":
    unittest.main()
