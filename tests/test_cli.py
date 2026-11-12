import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

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


if __name__ == "__main__":
    unittest.main()
