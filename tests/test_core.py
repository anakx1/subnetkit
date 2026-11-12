import json
import ipaddress
import unittest

from subnetkit import core


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
            with self.subTest(bad=bad):
                with self.assertRaises(core.InputError):
                    core.describe(bad)


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
        with self.assertRaises(core.InputError):
            core.vlsm("10.0.0.0/30", [{"name": "too-big", "hosts": 10}])

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

    def test_range_rejected(self):
        data = core.check_relations("10.0.0.0/8", ["10.0.0.1 - 10.0.0.5"])
        self.assertEqual(data["results"][0]["relation"], "unsupported")


if __name__ == "__main__":
    unittest.main()
