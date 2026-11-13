import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from subnetkit import cli


def run(*args):
    output = io.StringIO()
    errors = io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        code = cli.main(list(args))
    return code, output.getvalue()


class CliTests(unittest.TestCase):
    def test_default_command(self):
        code, output = run("--json", "192.168.1.10/24")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["cidr"], "192.168.1.0/24")

    def test_range_with_separate_arguments(self):
        code, output = run("--json", "10.0.0.5", "-", "10.0.0.42")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["kind"], "range")
        self.assertEqual(data["total_addresses"], 38)

    def test_split_json(self):
        code, output = run("split", "192.168.1.0/24", "-n", "4", "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["generated_count"], 4)
        self.assertNotIn("_all", data)

    def test_mask_json(self):
        code, output = run("mask", "0.0.0.255", "--json")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["prefix"], 24)
        self.assertEqual(data["input_kind"], "wildcard")

    def test_error_exit_code(self):
        code, output = run("--json", "999.1.1.1")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_multiple_targets(self):
        code, output = run("--json", "10.0.0.0/8", "192.168.0.0/16")
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(len(data), 2)

    def test_vlsm_options_json(self):
        code, output = run(
            "vlsm",
            "10.0.0.0/24",
            "--classic",
            "--gateway",
            "--growth",
            "20",
            "LAN:2",
            "WAN:1",
            "--json",
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertTrue(data["classic"])
        self.assertTrue(data["gateway"])
        self.assertEqual(data["growth_percent"], 20)
        by_name = {item["name"]: item for item in data["allocations"]}
        self.assertEqual(by_name["LAN"]["effective_hosts"], 4)
        self.assertEqual(by_name["WAN"]["effective_hosts"], 3)
        self.assertTrue(all(item["prefix"] == 29 for item in data["allocations"]))

    def test_merge_json(self):
        code, output = run(
            "merge", "10.0.0.0/25", "10.0.0.128/25", "--json"
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["cidr_list"], ["10.0.0.0/24"])

    def test_exclude_json(self):
        code, output = run(
            "exclude", "10.0.0.0/24", "10.0.0.64/26", "--json"
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(
            data["cidr_list"], ["10.0.0.0/26", "10.0.0.128/25"]
        )

    def test_diff_json(self):
        code, output = run(
            "diff", "10.0.0.0/24", "10.0.0.0/25", "--json"
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["only_a"], ["10.0.0.128/25"])
        self.assertEqual(data["both"], ["10.0.0.0/25"])

    def test_global_json_for_new_commands(self):
        code, output = run(
            "--json", "merge", "10.0.0.0/31", "10.0.0.2/32"
        )
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual(data["kind"], "merge")

    def test_new_command_error_exit_code(self):
        code, output = run("merge", "not-an-ip", "--json")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_plan_workflow_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "office.json")

            code, output = run("plan", "init", path, "10.0.0.0/16", "--json")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["parent"], "10.0.0.0/16")

            code, output = run(
                "plan", "add", path, "LAN", "100", "--vlan", "10", "--json"
            )
            self.assertEqual(code, 0)
            data = json.loads(output)
            self.assertEqual(data["cidr"], "10.0.0.0/25")
            self.assertEqual(data["subnet"]["vlan"], 10)
            self.assertEqual(data["plan"]["subnets"][0]["name"], "LAN")

            code, output = run("plan", "free", path, "--json")
            self.assertEqual(code, 0)
            self.assertEqual(
                json.loads(output)["free_blocks"][0], "10.0.0.128/25"
            )

            code, output = run("plan", "validate", path, "--json")
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(output)["valid"])

            code, output = run("--json", "plan", "show", path)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)["subnet_count"], 1)

            code, output = run("plan", "export", path, "--format", "csv")
            self.assertEqual(code, 0)
            self.assertTrue(output.startswith("name,cidr,vlan,notes\n"))

    def test_plan_validate_invalid_returns_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(
                json.dumps(
                    {
                        "parent": "10.0.0.0/24",
                        "subnets": [
                            {
                                "name": "A",
                                "cidr": "10.0.0.0/25",
                                "vlan": 10,
                            },
                            {
                                "name": "B",
                                "cidr": "10.0.0.0/26",
                                "vlan": 10,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            code, output = run("plan", "validate", str(path), "--json")
            self.assertEqual(code, 1)
            data = json.loads(output)
            self.assertFalse(data["valid"])
            codes = {error["code"] for error in data["errors"]}
            self.assertIn("overlap", codes)
            self.assertIn("duplicate-vlan", codes)

    def test_plan_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "plan.json")
            code, output = run("plan", "init", path, "10.0.0.0/16", "--json")
            self.assertEqual(code, 0)
            code, output = run("plan", "init", path, "10.0.0.0/8", "--json")
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            code, output = run(
                "plan", "export", path, "--format", "yaml"
            )
            self.assertEqual(code, 2)
            self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
