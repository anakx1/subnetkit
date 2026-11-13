import http.client
import io
import json
import threading
import unittest
from contextlib import redirect_stderr
from unittest import mock

from subnetkit import web


class HostAllowlistTests(unittest.TestCase):
    def test_normalise_host(self):
        cases = {
            "LOCALHOST": "localhost",
            "localhost:8765": "localhost",
            "localhost.": "localhost",
            "127.0.0.1": "127.0.0.1",
            "127.0.0.1:8765": "127.0.0.1",
            "[::1]": "::1",
            "[::1]:8765": "::1",
            "0:0:0:0:0:0:0:1": "::1",
            "evil.example:80": "evil.example",
            "": "",
            None: "",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(web._normalise_host(raw), expected)

    def test_bind_host_is_allowed(self):
        hosts = web._allowed_hosts("custom.test")
        self.assertIn("custom.test", hosts)
        self.assertIn("localhost", hosts)
        self.assertIn("127.0.0.1", hosts)
        self.assertIn("::1", hosts)
        self.assertIn("0.0.0.0", web._allowed_hosts("0.0.0.0"))


class WebTests(unittest.TestCase):
    server: web.SubnetkitHTTPServer
    port: int
    thread: threading.Thread

    @classmethod
    def setUpClass(cls):
        cls.server = web.create_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            name="subnetkit-test-web",
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read()
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def get(self, path, host=None):
        headers = {} if host is None else {"Host": host}
        return self.request("GET", path, headers=headers)

    def post(self, path, payload, host=None, content_type="application/json"):
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Length": str(len(body))}
        if host is not None:
            headers["Host"] = host
        if content_type is not None:
            headers["Content-Type"] = content_type
        return self.request("POST", path, body=body, headers=headers)

    def body_json(self, body):
        return json.loads(body.decode("utf-8"))

    def test_api_health_and_allowed_hosts(self):
        hosts = (
            "localhost",
            f"localhost:{self.port}",
            "127.0.0.1",
            f"127.0.0.1:{self.port}",
            "[::1]",
            f"[::1]:{self.port}",
            "LOCALHOST",
        )
        for host in hosts:
            with self.subTest(host=host):
                status, _, body = self.get("/api/health", host=host)
                self.assertEqual(status, 200)
                self.assertEqual(
                    self.body_json(body)["data"]["status"], "ok"
                )

    def test_bad_host_is_forbidden(self):
        for host in (
            "evil.example",
            "evil.example:80",
            "localhost.evil.example",
            "127.0.0.1.evil.example",
            "[::1]evil",
        ):
            with self.subTest(host=host):
                status, _, body = self.get("/api/health", host=host)
                self.assertEqual(status, 403)
                self.assertFalse(self.body_json(body)["ok"])

        status, _, _ = self.post(
            "/api/inspect",
            {"input": "10.0.0.0/8"},
            host="evil.example",
        )
        self.assertEqual(status, 403)

    def test_all_api_routes(self):
        cases = (
            (
                "/api/inspect",
                {"input": "192.168.1.10/24"},
                lambda data: data["cidr"] == "192.168.1.0/24",
            ),
            (
                "/api/split",
                {"target": "192.168.1.0/24", "count": 4},
                lambda data: data["generated_count"] == 4,
            ),
            (
                "/api/summarize",
                {"start": "192.168.1.5", "end": "192.168.1.10"},
                lambda data: data["kind"] == "range",
            ),
            (
                "/api/mask",
                {"mask": "255.255.255.192"},
                lambda data: data["prefix"] == 26,
            ),
            (
                "/api/vlsm",
                {
                    "target": "192.168.1.0/24",
                    "requirements": [
                        {"name": "LAN", "hosts": 100},
                        {"name": "WAN", "hosts": 2},
                    ],
                },
                lambda data: len(data["allocations"]) == 2,
            ),
            (
                "/api/check",
                {
                    "target": "10.0.0.0/8",
                    "others": ["10.1.2.3", "192.168.0.0/16"],
                },
                lambda data: data["results"][0]["relation"] == "inside",
            ),
            (
                "/api/merge",
                {"inputs": ["10.0.0.0/25", "10.0.0.128/25"]},
                lambda data: data["cidr_list"] == ["10.0.0.0/24"],
            ),
            (
                "/api/exclude",
                {"base": "10.0.0.0/24", "exclude": ["10.0.0.64/26"]},
                lambda data: data["cidr_count"] == 2,
            ),
            (
                "/api/diff",
                {"a": "10.0.0.0/24", "b": "10.0.0.0/25"},
                lambda data: data["only_a"] == ["10.0.0.128/25"],
            ),
        )
        for path, payload, check in cases:
            with self.subTest(path=path):
                status, _, body = self.post(path, payload)
                self.assertEqual(status, 200)
                response = self.body_json(body)
                self.assertTrue(response["ok"])
                self.assertTrue(check(response["data"]))

    def test_vlsm_options_api(self):
        status, _, body = self.post(
            "/api/vlsm",
            {
                "target": "10.0.0.0/24",
                "requirements": [
                    {"name": "LAN", "hosts": 2},
                    {"name": "WAN", "hosts": 1},
                ],
                "classic": True,
                "gateway": True,
                "growth": 20,
            },
        )
        self.assertEqual(status, 200)
        data = self.body_json(body)["data"]
        self.assertTrue(data["classic"])
        self.assertTrue(data["gateway"])
        self.assertEqual(data["growth_percent"], 20)
        by_name = {item["name"]: item for item in data["allocations"]}
        self.assertEqual(by_name["LAN"]["effective_hosts"], 4)
        self.assertEqual(by_name["WAN"]["effective_hosts"], 3)
        self.assertTrue(all(item["prefix"] == 29 for item in data["allocations"]))

    def test_check_range_api(self):
        status, _, body = self.post(
            "/api/check",
            {
                "target": "10.0.0.0/8",
                "others": ["10.0.0.1 - 10.0.0.5"],
            },
        )
        self.assertEqual(status, 200)
        result = self.body_json(body)["data"]["results"][0]
        self.assertEqual(result["type"], "range")
        self.assertEqual(result["relation"], "inside")
        self.assertTrue(result["cidr_list"])

    def test_plan_api_workflow(self):
        status, _, body = self.post(
            "/api/plan/init", {"parent": "10.0.0.0/16"}
        )
        self.assertEqual(status, 200)
        created = self.body_json(body)["data"]
        self.assertEqual(created["parent"], "10.0.0.0/16")

        status, _, body = self.post(
            "/api/plan/add",
            {
                "plan": created,
                "name": "LAN",
                "hosts": 100,
                "vlan": 10,
            },
        )
        self.assertEqual(status, 200)
        added = self.body_json(body)["data"]
        self.assertEqual(added["cidr"], "10.0.0.0/25")
        self.assertEqual(added["plan"]["subnets"][0]["name"], "LAN")
        self.assertEqual(added["free_blocks"][0], "10.0.0.128/25")

        status, _, body = self.post(
            "/api/plan/free", {"plan": added["plan"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            self.body_json(body)["data"]["free_blocks"][0],
            "10.0.0.128/25",
        )

        status, _, body = self.post(
            "/api/plan/validate", {"plan": added["plan"]}
        )
        self.assertEqual(status, 200)
        self.assertTrue(self.body_json(body)["data"]["valid"])

        status, _, body = self.post(
            "/api/plan/show", {"plan": added["plan"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.body_json(body)["data"]["subnet_count"], 1)

        status, _, body = self.post(
            "/api/plan/export",
            {"plan": added["plan"], "format": "csv"},
        )
        self.assertEqual(status, 200)
        exported = self.body_json(body)["data"]
        self.assertEqual(exported["format"], "csv")
        self.assertIn("name,cidr,vlan,notes", exported["text"])

        status, _, body = self.post(
            "/api/plan",
            {"action": "free", "plan": added["plan"]},
        )
        self.assertEqual(status, 200)
        self.assertTrue(self.body_json(body)["data"]["free_blocks"])

    def test_plan_api_errors(self):
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            ("/api/plan/init", {"parent": "not-a-network"}),
            ("/api/plan/add", {"name": "LAN", "hosts": 10}),
            ("/api/plan/free", {}),
            ("/api/plan/validate", {"plan": {"subnets": []}}),
            ("/api/plan/export", {"plan": {"parent": "10.0.0.0/16"}, "format": "yaml"}),
            ("/api/plan", {"action": "nope"}),
        )
        for path, payload in cases:
            with self.subTest(path=path):
                status, _, body = self.post(path, payload)
                self.assertEqual(status, 400)
                self.assertFalse(self.body_json(body)["ok"])

    def test_static_planner_controls(self):
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        for control in (
            "tab-plan",
            "panel-plan",
            "plan-parent",
            "plan-name",
            "plan-hosts",
            "plan-export-format",
            "plan-export",
        ):
            self.assertIn(control, page)

        status, _, body = self.get("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode("utf-8")
        for token in ("renderPlanView", "runPlanInit", "planValidationCard"):
            self.assertIn(token, script)

    def test_static_shareable_theme_and_downloads(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        for control in ("theme-toggle", "theme-icon", "theme-label"):
            self.assertIn(control, page)
        self.assertNotIn(" style=", page)
        self.assertNotIn("onclick=", page)
        csp = headers["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)

        status, _, body = self.get("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode("utf-8")
        for token in (
            "addressMapHtml",
            "downloadButtons",
            "encodeHashState",
            "applyTheme",
            "localStorage",
            "history.replaceState",
            "map-readout",
        ):
            self.assertIn(token, script)

        status, _, body = self.get("/static/styles.css")
        self.assertEqual(status, 200)
        styles = body.decode("utf-8")
        for token in (
            'html[data-theme="light"]',
            ".map-bar",
            ".map-grid",
            ".theme-toggle",
        ):
            self.assertIn(token, styles)

    def test_bad_input_returns_400(self):
        cases = (
            ("/api/inspect", {"input": "999.1.1.1"}),
            ("/api/split", {"target": "192.168.1.0/24"}),
            ("/api/summarize", {"start": "not-an-ip"}),
            ("/api/mask", {"mask": "not-a-mask"}),
            (
                "/api/vlsm",
                {"target": "192.168.1.0/24", "requirements": []},
            ),
            ("/api/check", {"target": "not-a-network", "others": []}),
            (
                "/api/vlsm",
                {
                    "target": "10.0.0.0/24",
                    "requirements": [{"name": "A", "hosts": 1}],
                    "growth": -1,
                },
            ),
            (
                "/api/merge",
                {"inputs": ["10.0.0.0/8", "2001:db8::/32"]},
            ),
            ("/api/exclude", {"base": "not-a-network", "exclude": []}),
            ("/api/diff", {"a": "10.0.0.0/8", "b": "2001:db8::/32"}),
        )
        for path, payload in cases:
            with self.subTest(path=path):
                status, _, body = self.post(path, payload)
                self.assertEqual(status, 400)
                response = self.body_json(body)
                self.assertFalse(response["ok"])
                self.assertTrue(response["error"])

    def test_invalid_json_and_non_object_bodies(self):
        status, _, body = self.request(
            "POST",
            "/api/inspect",
            body=b"{",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "1",
            },
        )
        self.assertEqual(status, 400)
        self.assertFalse(self.body_json(body)["ok"])

        status, _, body = self.post("/api/inspect", ["not", "an", "object"])
        self.assertEqual(status, 400)
        self.assertFalse(self.body_json(body)["ok"])

    def test_not_found(self):
        for method, path in (
            ("GET", "/nope"),
            ("GET", "/api/nope"),
            ("POST", "/api/nope"),
            ("GET", "/static/missing.js"),
        ):
            with self.subTest(method=method, path=path):
                if method == "POST":
                    status, _, body = self.post(path, {})
                else:
                    status, _, body = self.get(path)
                self.assertEqual(status, 404)
                self.assertFalse(self.body_json(body)["ok"])

    def test_wrong_content_type_returns_415(self):
        for content_type in ("text/plain", "application/x-www-form-urlencoded", None):
            with self.subTest(content_type=content_type):
                status, _, body = self.post(
                    "/api/inspect",
                    {"input": "10.0.0.0/8"},
                    content_type=content_type,
                )
                self.assertEqual(status, 415)
                self.assertFalse(self.body_json(body)["ok"])

    def test_oversized_body_returns_400(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5
        )
        try:
            connection.putrequest(
                "POST",
                "/api/inspect",
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", f"127.0.0.1:{self.port}")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(web.MAX_BODY + 1))
            connection.endheaders()
            response = connection.getresponse()
            data = response.read()
        finally:
            connection.close()

        self.assertEqual(response.status, 400)
        self.assertFalse(self.body_json(data)["ok"])

    def test_static_files(self):
        cases = (
            ("/", "text/html"),
            ("/index.html", "text/html"),
            ("/static/app.js", "text/javascript"),
            ("/static/styles.css", "text/css"),
        )
        for path, content_type in cases:
            with self.subTest(path=path):
                status, headers, body = self.get(path)
                self.assertEqual(status, 200)
                self.assertTrue(
                    headers["Content-Type"].startswith(content_type)
                )
                self.assertTrue(body)

    def test_static_vlsm_controls(self):
        status, _, body = self.get("/")
        self.assertEqual(status, 200)
        page = body.decode("utf-8")
        for control in (
            "vlsm-classic",
            "vlsm-gateway",
            "vlsm-growth",
        ):
            self.assertIn(control, page)

        status, _, body = self.get("/static/app.js")
        self.assertEqual(status, 200)
        script = body.decode("utf-8")
        for token in ("effective_hosts", "host_position", "reverse_dns"):
            self.assertIn(token, script)

    def test_static_path_traversal(self):
        for path in (
            "/static/../x",
            "/static/../index.html",
            "/static/../subnetkit/web.py",
            "/static/%2e%2e/index.html",
            "/static/..%2fx",
        ):
            with self.subTest(path=path):
                status, _, body = self.get(path)
                self.assertEqual(status, 404)
                self.assertFalse(self.body_json(body)["ok"])

    def test_internal_error_is_not_leaked(self):
        def boom(payload):
            raise RuntimeError("secret-marker")

        errors = io.StringIO()
        with mock.patch.dict(web.ROUTES, {"/api/inspect": boom}), redirect_stderr(errors):
            status, _, body = self.post(
                "/api/inspect", {"input": "10.0.0.0/8"}
            )

        self.assertEqual(status, 500)
        response = self.body_json(body)
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"], "Internal server error.")
        self.assertNotIn("secret-marker", body.decode("utf-8"))
        self.assertIn("secret-marker", errors.getvalue())
        self.assertIn("Traceback", errors.getvalue())

    def test_vlsm_requirement_limit(self):
        requirements = [
            {"name": f"subnet-{index}", "hosts": 1}
            for index in range(web.MAX_VLSM_REQUIREMENTS + 1)
        ]
        status, _, body = self.post(
            "/api/vlsm",
            {"target": "10.0.0.0/8", "requirements": requirements},
        )
        self.assertEqual(status, 400)
        response = self.body_json(body)
        self.assertIn("limit is 1000", response["error"])

    def test_check_others_limit(self):
        others = ["10.0.0.1"] * (web.MAX_CHECK_OTHERS + 1)
        status, _, body = self.post(
            "/api/check",
            {"target": "10.0.0.0/8", "others": others},
        )
        self.assertEqual(status, 400)
        response = self.body_json(body)
        self.assertIn("limit is 5000", response["error"])


if __name__ == "__main__":
    unittest.main()
