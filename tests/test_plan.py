import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from subnetkit import core, plan


class PlanFileTests(unittest.TestCase):
    def test_init_load_save_and_force(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            created = plan.init_plan(path, "10.0.0.0/16")
            self.assertEqual(created, {"parent": "10.0.0.0/16", "subnets": []})
            self.assertEqual(plan.load_plan(path), created)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"parent": "10.0.0.0/16", "subnets": []},
            )

            with self.assertRaises(core.InputError):
                plan.init_plan(path, "10.0.0.0/8")
            replaced = plan.init_plan(path, "10.0.0.0/8", force=True)
            self.assertEqual(replaced["parent"], "10.0.0.0/8")

    def test_save_and_load_preserve_notes_and_null_vlan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            source = {
                "parent": "10.0.0.0/16",
                "subnets": [
                    {
                        "name": "LAN",
                        "cidr": "10.0.0.0/24",
                        "vlan": 10,
                        "notes": "main floor",
                    },
                    {
                        "name": "WAN",
                        "cidr": "10.0.1.0/30",
                        "vlan": None,
                        "notes": "",
                    },
                ],
            }
            plan.save_plan(path, source)
            self.assertEqual(plan.load_plan(path), source)

    def test_load_rejects_bad_json_and_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(core.InputError):
                plan.load_plan(path)
            path.write_text('{"parent": "10.0.0.0/16", "subnets": {}}', encoding="utf-8")
            with self.assertRaises(core.InputError):
                plan.load_plan(path)


class PlanAllocationTests(unittest.TestCase):
    def test_best_fit_allocation_order(self):
        current = plan.new_plan("10.0.0.0/16")
        plan.add_subnet(current, "LAN", 100, vlan=10)
        plan.add_subnet(current, "WAN", 2, vlan=99)
        plan.add_subnet(current, "Guest", 20, vlan=20)

        by_name = {entry["name"]: entry["cidr"] for entry in current["subnets"]}
        self.assertEqual(by_name["LAN"], "10.0.0.0/25")
        self.assertEqual(by_name["WAN"], "10.0.0.128/31")
        self.assertEqual(by_name["Guest"], "10.0.0.160/27")

    def test_best_fit_uses_smallest_free_block(self):
        current = plan.new_plan("10.0.0.0/24")
        plan.add_subnet(current, "A", 62)
        plan.add_subnet(current, "B", 14)
        plan.add_subnet(current, "C", 6)

        by_name = {entry["name"]: entry["cidr"] for entry in current["subnets"]}
        self.assertEqual(by_name["A"], "10.0.0.0/26")
        self.assertEqual(by_name["B"], "10.0.0.64/28")
        self.assertEqual(by_name["C"], "10.0.0.80/29")

    def test_classic_and_gateway_allocation(self):
        current = plan.new_plan("10.0.0.0/24")
        classic = plan.add_subnet(current, "Classic", 2, classic=True)
        gateway = plan.add_subnet(current, "Gateway", 2, gateway=True)

        self.assertEqual(classic["cidr"], "10.0.0.0/30")
        self.assertEqual(gateway["cidr"], "10.0.0.8/29")

    def test_free_space_and_empty_plan(self):
        empty = plan.new_plan("10.0.0.0/24")
        empty_free = plan.free_space(empty)
        self.assertEqual(empty_free["free_blocks"], ["10.0.0.0/24"])
        self.assertEqual(empty_free["free_addresses"], 256)
        self.assertEqual(empty_free["allocated_addresses"], 0)

        plan.add_subnet(empty, "LAN", 100)
        free = plan.free_space(empty)
        self.assertEqual(free["free_blocks"], ["10.0.0.128/25"])
        self.assertEqual(free["free_count"], 1)
        self.assertEqual(free["free_addresses"], 128)
        self.assertEqual(free["allocated_addresses"], 128)
        self.assertEqual(plan.free_blocks(empty), ["10.0.0.128/25"])

    def test_ipv6_allocation_and_free_space(self):
        current = plan.new_plan("2001:db8::/48")
        entry = plan.add_subnet(current, "v6", 100, vlan=6)
        self.assertTrue(entry["cidr"].startswith("2001:db8::/"))
        free = plan.free_space(current)
        self.assertTrue(free["free_blocks"])
        self.assertNotIn(entry["cidr"], free["free_blocks"])

    def test_edge_prefix_allocations(self):
        current = plan.new_plan("10.0.0.0/31")
        self.assertEqual(
            plan.add_subnet(current, "A", 1)["cidr"], "10.0.0.0/32"
        )
        self.assertEqual(
            plan.add_subnet(current, "B", 1)["cidr"], "10.0.0.1/32"
        )
        with self.assertRaises(core.InputError):
            plan.add_subnet(current, "C", 1)

        host_route = plan.new_plan("10.0.0.7/32")
        self.assertEqual(
            plan.add_subnet(host_route, "host", 1)["cidr"], "10.0.0.7/32"
        )
        self.assertEqual(plan.free_space(host_route)["free_blocks"], [])

        all_v4 = plan.new_plan("0.0.0.0/0")
        self.assertEqual(
            plan.add_subnet(all_v4, "first", 1)["cidr"], "0.0.0.0/32"
        )
        self.assertTrue(plan.free_space(all_v4)["free_blocks"])

    def test_duplicates_and_no_space_are_errors(self):
        current = plan.new_plan("10.0.0.0/24")
        plan.add_subnet(current, "LAN", 100, vlan=10)
        with self.assertRaises(core.InputError):
            plan.add_subnet(current, "LAN", 10)
        with self.assertRaises(core.InputError):
            plan.add_subnet(current, "OTHER", 10, vlan=10)
        with self.assertRaises(core.InputError):
            plan.add_subnet(current, "HUGE", 200)

    def test_add_to_file_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            plan.init_plan(path, "10.0.0.0/16")
            entry = plan.add_to_file(path, "LAN", 100, vlan=10)
            self.assertEqual(entry["cidr"], "10.0.0.0/25")
            loaded = plan.load_plan(path)
            self.assertEqual(loaded["subnets"], [entry])
            self.assertEqual(plan.free_file(path)["free_blocks"][0], "10.0.0.128/25")


class PlanValidationTests(unittest.TestCase):
    def test_valid_plan(self):
        current = {
            "parent": "10.0.0.0/16",
            "subnets": [
                {"name": "LAN", "cidr": "10.0.0.0/24", "vlan": 10, "notes": ""},
                {"name": "WAN", "cidr": "10.0.1.0/30", "vlan": 99, "notes": ""},
            ],
        }
        report = plan.validate_plan(current)
        self.assertTrue(report["valid"])
        self.assertTrue(report["ok"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["subnet_count"], 2)

    def test_overlap_outside_duplicates_and_invalid_values(self):
        current = {
            "parent": "10.0.0.0/24",
            "subnets": [
                {"name": "A", "cidr": "10.0.0.0/25", "vlan": 10},
                {"name": "A", "cidr": "10.0.0.128/25", "vlan": 10},
                {"name": "outside", "cidr": "10.0.1.0/24"},
                {"name": "overlap", "cidr": "10.0.0.0/26", "vlan": 20},
                {"name": "bad", "cidr": "not-a-cidr"},
                {"name": "mixed", "cidr": "2001:db8::/64"},
            ],
        }
        report = plan.validate_plan(current)
        self.assertFalse(report["valid"])
        codes = {error["code"] for error in report["errors"]}
        self.assertIn("duplicate-name", codes)
        self.assertIn("duplicate-vlan", codes)
        self.assertIn("outside-parent", codes)
        self.assertIn("overlap", codes)
        self.assertIn("invalid-cidr", codes)
        self.assertEqual(
            len(report["errors"]),
            len(report["error_messages"]),
        )

    def test_invalid_parent(self):
        report = plan.validate_plan(
            {
                "parent": "not-a-network",
                "subnets": [
                    {"name": "A", "cidr": "10.0.0.0/24", "vlan": None},
                ],
            }
        )
        self.assertFalse(report["valid"])
        self.assertEqual(report["errors"][0]["code"], "invalid-parent")
        self.assertIsNone(report["version"])


class PlanExportTests(unittest.TestCase):
    def setUp(self):
        self.current = {
            "parent": "10.0.0.0/16",
            "subnets": [
                {
                    "name": "LAN",
                    "cidr": "10.0.0.0/24",
                    "vlan": 10,
                    "notes": "main floor",
                },
                {
                    "name": "WAN",
                    "cidr": "10.0.1.0/30",
                    "vlan": None,
                    "notes": "",
                },
            ],
        }

    def test_csv_and_json(self):
        csv_text = plan.export_plan(self.current, "csv")
        rows = list(csv.reader(io.StringIO(csv_text)))
        self.assertEqual(rows[0], ["name", "cidr", "vlan", "notes"])
        self.assertEqual(rows[1], ["LAN", "10.0.0.0/24", "10", "main floor"])
        self.assertEqual(rows[2], ["WAN", "10.0.1.0/30", "", ""])

        exported = json.loads(plan.export_plan(self.current, "json"))
        self.assertEqual(exported, self.current)

    def test_cisco_iproute2_and_terraform(self):
        cisco = plan.export_plan(self.current, "cisco")
        self.assertIn("interface Vlan10", cisco)
        self.assertIn("ip address 10.0.0.1 255.255.255.0", cisco)
        self.assertIn("10.0.0.0/24", cisco)

        iproute2 = plan.export_plan(self.current, "iproute2")
        self.assertIn("ip route add 10.0.0.0/24 dev vlan10", iproute2)
        self.assertIn("ip route add 10.0.1.0/30 dev wan", iproute2)

        terraform = plan.export_plan(self.current, "terraform")
        self.assertIn('"LAN" = {', terraform)
        self.assertIn('cidr_block = "10.0.0.0/24"', terraform)
        self.assertIn("vlan = 10", terraform)
        self.assertIn('notes = "main floor"', terraform)

    def test_ipv6_exports(self):
        current = {
            "parent": "2001:db8::/48",
            "subnets": [
                {
                    "name": "v6",
                    "cidr": "2001:db8::/64",
                    "vlan": None,
                    "notes": "",
                }
            ],
        }
        self.assertIn("ipv6 address 2001:db8::1/64", plan.export_plan(current, "cisco"))
        self.assertIn(
            "ip -6 route add 2001:db8::/64 dev v6",
            plan.export_plan(current, "iproute2"),
        )
        self.assertIn(
            'cidr_block = "2001:db8::/64"',
            plan.export_plan(current, "terraform"),
        )

    def test_unknown_format_and_empty_plan(self):
        with self.assertRaises(core.InputError):
            plan.export_plan(self.current, "yaml")
        empty = plan.new_plan("10.0.0.0/24")
        self.assertEqual(
            plan.export_plan(empty, "csv"),
            "name,cidr,vlan,notes\n",
        )
        self.assertEqual(
            json.loads(plan.export_plan(empty, "json")),
            {"parent": "10.0.0.0/24", "subnets": []},
        )


if __name__ == "__main__":
    unittest.main()
