"""Local web UI and JSON API for subnetkit."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import sys
import threading
import traceback
import webbrowser
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import core, plan

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 1 << 20
MAX_VLSM_REQUIREMENTS = 1000
MAX_CHECK_OTHERS = 5000
MAX_PLAN_SUBNETS = 5000
DEFAULT_ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


def _normalise_host(value: str | None) -> str:
    """Return a canonical host name without a port, or '' if invalid."""
    text = (value or "").strip().lower()
    if not text:
        return ""
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return ""
        host = text[1:end]
        rest = text[end + 1:]
        if rest and not (rest.startswith(":") and rest[1:].isdigit()):
            return ""
        text = host
    elif text.count(":") == 1:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    text = text.rstrip(".")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _allowed_hosts(host: str, extra: Iterable[str] | None = None) -> frozenset[str]:
    hosts = set(DEFAULT_ALLOWED_HOSTS)
    hosts.add(_normalise_host(host))
    if isinstance(extra, str):
        extra = [extra]
    for item in extra or ():
        hosts.add(_normalise_host(item))
    hosts.discard("")
    return frozenset(hosts)


def _str(payload: dict, key: str, default: str = "") -> str:
    value = payload.get(key, default)
    if value is None:
        return default
    return str(value)


def _int_or_none(payload: dict, key: str):
    value = payload.get(key)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise core.InputError(f"'{key}' must be a whole number.") from exc


def _bool(payload: dict, key: str, default: bool = False) -> bool:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _float(payload: dict, key: str, default: float = 0.0) -> float:
    value = payload.get(key, default)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise core.InputError(f"'{key}' must be a number.") from exc


def _payload_list(payload: dict, *keys: str):
    for key in keys:
        if key in payload:
            return payload[key]
    return []


def _requirements(payload: dict) -> list[dict]:
    value = payload.get("requirements")
    if isinstance(value, str):
        lines = [line.strip() for line in value.splitlines() if line.strip()]
        if len(lines) > MAX_VLSM_REQUIREMENTS:
            raise core.InputError(
                f"Too many VLSM requirements ({len(lines)}); "
                f"the limit is {MAX_VLSM_REQUIREMENTS}."
            )
        items: list[dict] = []
        for index, line in enumerate(lines, 1):
            if ":" in line:
                name, hosts = line.rsplit(":", 1)
            elif "," in line:
                name, hosts = line.rsplit(",", 1)
            else:
                name, hosts = f"subnet-{index}", line
            try:
                items.append({"name": name.strip() or f"subnet-{index}", "hosts": int(hosts)})
            except ValueError as exc:
                raise core.InputError(
                    f"'{line}' does not end in a host count."
                ) from exc
        return items
    if isinstance(value, list):
        if len(value) > MAX_VLSM_REQUIREMENTS:
            raise core.InputError(
                f"Too many VLSM requirements ({len(value)}); "
                f"the limit is {MAX_VLSM_REQUIREMENTS}."
            )
        result = []
        for index, item in enumerate(value, 1):
            if not isinstance(item, dict):
                raise core.InputError("Each requirement needs a name and hosts.")
            try:
                host_count = int(item.get("hosts", 0))
            except (TypeError, ValueError) as exc:
                raise core.InputError("Host counts must be whole numbers.") from exc
            result.append(
                {
                    "name": str(item.get("name") or f"subnet-{index}"),
                    "hosts": host_count,
                }
            )
        return result
    raise core.InputError("Add at least one requirement.")


def _others(payload: dict) -> list[str]:
    value = payload.get("others", [])
    if isinstance(value, str):
        pieces: list[str] = []
        for line in value.splitlines():
            pieces.extend(part.strip() for part in line.split(",") if part.strip())
        if len(pieces) > MAX_CHECK_OTHERS:
            raise core.InputError(
                f"Too many 'others' entries ({len(pieces)}); "
                f"the limit is {MAX_CHECK_OTHERS}."
            )
        return pieces
    if isinstance(value, list):
        if len(value) > MAX_CHECK_OTHERS:
            raise core.InputError(
                f"Too many 'others' entries ({len(value)}); "
                f"the limit is {MAX_CHECK_OTHERS}."
            )
        return [str(item) for item in value if str(item).strip()]
    return []


def api_inspect(payload: dict):
    return core.describe(_str(payload, "input"))


def api_split(payload: dict):
    return core.split_network(
        _str(payload, "target"),
        count=_int_or_none(payload, "count"),
        prefix=_int_or_none(payload, "prefix"),
    )


def api_summarize(payload: dict):
    start = _str(payload, "start") or _str(payload, "input")
    end = _str(payload, "end")
    if end:
        return core.summarize(start, end)
    return core.summarize(start)


def api_mask(payload: dict):
    try:
        version = int(payload.get("version", 4))
    except (TypeError, ValueError):
        version = 4
    return core.mask_info(_str(payload, "mask"), 6 if version == 6 else 4)


def api_vlsm(payload: dict):
    options = payload.get("options")
    if not isinstance(options, dict):
        options = {}
    return core.vlsm(
        _str(payload, "target"),
        _requirements(payload),
        classic=_bool(payload, "classic", _bool(options, "classic")),
        gateway=_bool(payload, "gateway", _bool(options, "gateway")),
        growth=_float(
            payload,
            "growth",
            _float(
                payload,
                "growth_percent",
                _float(options, "growth", 0.0),
            ),
        ),
    )


def api_check(payload: dict):
    return core.check_relations(_str(payload, "target"), _others(payload))


def api_merge(payload: dict):
    return core.merge(
        _payload_list(
            payload, "inputs", "input", "items", "networks", "cidrs"
        )
    )


def api_exclude(payload: dict):
    base = _str(payload, "base") or _str(payload, "target")
    items = _payload_list(
        payload,
        "exclude",
        "subtract",
        "remove",
        "items",
        "networks",
        "cidrs",
    )
    return core.exclude(base, items)


def api_diff(payload: dict):
    a = _str(payload, "a") or _str(payload, "left") or _str(payload, "first")
    b = _str(payload, "b") or _str(payload, "right") or _str(payload, "second")
    return core.diff(a, b)


def _plan_payload(payload: dict) -> dict:
    """Extract an in-memory plan from an API request.

    The web API deliberately does not accept filesystem paths: the browser
    keeps the plan in memory and sends it back with each operation.
    """
    value = payload.get("plan")
    if value is None and isinstance(payload.get("parent"), str):
        value = {
            "parent": payload.get("parent"),
            "subnets": payload.get("subnets", []),
        }
    if not isinstance(value, dict):
        raise core.InputError("Provide a plan object with parent and subnets.")
    subnets = value.get("subnets", [])
    if isinstance(subnets, list) and len(subnets) > MAX_PLAN_SUBNETS:
        raise core.InputError(
            f"Too many plan subnets ({len(subnets)}); "
            f"the limit is {MAX_PLAN_SUBNETS}."
        )
    return value


def api_plan_init(payload: dict):
    return plan.new_plan(_str(payload, "parent"))


def api_plan_add(payload: dict):
    current = _plan_payload(payload)
    details = payload.get("subnet")
    if not isinstance(details, dict):
        details = {}
    name = _str(details, "name") or _str(payload, "name")
    hosts = (
        _int_or_none(details, "hosts")
        if details.get("hosts") is not None
        else _int_or_none(payload, "hosts")
    )
    vlan = (
        _int_or_none(details, "vlan")
        if details.get("vlan") is not None
        else _int_or_none(payload, "vlan")
    )
    entry = plan.add_subnet(
        current,
        name,
        hosts,
        vlan=vlan,
        classic=_bool(payload, "classic", _bool(details, "classic")),
        gateway=_bool(payload, "gateway", _bool(details, "gateway")),
    )
    free = plan.free_space(current)
    validation = plan.validate_plan(current)
    return {
        "kind": "plan-add",
        "parent": free["parent"],
        "subnet": entry,
        "name": entry["name"],
        "cidr": entry["cidr"],
        "vlan": entry["vlan"],
        "notes": entry["notes"],
        "plan": current,
        "free": free,
        "free_blocks": free["free_blocks"],
        "free_count": free["free_count"],
        "free_addresses": free["free_addresses"],
        "free_display": free["free_display"],
        "validation": validation,
    }


def api_plan_free(payload: dict):
    return plan.free_space(_plan_payload(payload))


def api_plan_validate(payload: dict):
    return plan.validate_plan(_plan_payload(payload))


def api_plan_show(payload: dict):
    return plan.show_plan(_plan_payload(payload))


def api_plan_export(payload: dict):
    format_name = _str(payload, "format") or _str(payload, "fmt") or "json"
    text = plan.export_plan(_plan_payload(payload), format_name)
    return {
        "kind": "plan-export",
        "format": format_name.lower(),
        "text": text,
        "content": text,
    }


_PLAN_ACTIONS = {
    "init": api_plan_init,
    "add": api_plan_add,
    "free": api_plan_free,
    "validate": api_plan_validate,
    "show": api_plan_show,
    "export": api_plan_export,
}


def api_plan(payload: dict):
    action = _str(payload, "action") or _str(payload, "op")
    try:
        handler = _PLAN_ACTIONS[action.lower()]
    except KeyError as exc:
        raise core.InputError(
            "Plan action must be init, add, free, validate, show, or export."
        ) from exc
    return handler(payload)


ROUTES = {
    "/api/inspect": api_inspect,
    "/api/split": api_split,
    "/api/summarize": api_summarize,
    "/api/mask": api_mask,
    "/api/vlsm": api_vlsm,
    "/api/check": api_check,
    "/api/merge": api_merge,
    "/api/exclude": api_exclude,
    "/api/diff": api_diff,
    "/api/plan": api_plan,
    "/api/plan/init": api_plan_init,
    "/api/plan/add": api_plan_add,
    "/api/plan/free": api_plan_free,
    "/api/plan/validate": api_plan_validate,
    "/api/plan/show": api_plan_show,
    "/api/plan/export": api_plan_export,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "subnetkit/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 10

    def log_message(self, fmt: str, *args) -> None:  # keep the terminal calm
        pass

    def _host_allowed(self) -> bool:
        host = _normalise_host(self.headers.get("Host"))
        allowed = getattr(self.server, "allowed_hosts", DEFAULT_ALLOWED_HOSTS)
        return host in allowed

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        cache: str = "no-store",
        close: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )
        if close:
            self.send_header("Connection", "close")
        self.end_headers()
        if close:
            self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict, close: bool = False) -> None:
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
            close=close,
        )

    def _serve_static(self, name: str) -> None:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            self._json(404, {"ok": False, "error": "Not found."})
            return
        root = STATIC_DIR.resolve()
        try:
            path = (root / name).resolve()
        except OSError:
            self._json(404, {"ok": False, "error": "Not found."})
            return
        if root not in path.parents or not path.is_file():
            self._json(404, {"ok": False, "error": "Not found."})
            return
        data = path.read_bytes()
        self._send(200, data, _MIME.get(path.suffix, "application/octet-stream"))

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._json(403, {"ok": False, "error": "Host not allowed."}, close=True)
            return
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._serve_static("index.html")
            return
        if path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
            return
        if path == "/api/health":
            self._json(200, {"ok": True, "data": {"status": "ok"}})
            return
        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return
        self._json(404, {"ok": False, "error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_allowed():
            self._json(403, {"ok": False, "error": "Host not allowed."}, close=True)
            return
        path = urlsplit(self.path).path
        route = ROUTES.get(path)
        if route is None:
            self._json(404, {"ok": False, "error": "Not found."}, close=True)
            return
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self._json(
                415,
                {"ok": False, "error": "Content-Type must be application/json."},
                close=True,
            )
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._json(
                400,
                {"ok": False, "error": "Missing or oversized request body."},
                close=True,
            )
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self._json(400, {"ok": False, "error": "Request body must be a JSON object."})
            return

        try:
            data = route(payload)
        except core.InputError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        except Exception:  # never leak a traceback to the browser
            traceback.print_exc(file=sys.stderr)
            self._json(500, {"ok": False, "error": "Internal server error."})
            return
        self._json(200, {"ok": True, "data": data})


class SubnetkitHTTPServer(ThreadingHTTPServer):
    """Threading HTTP server carrying the request Host allowlist."""

    allowed_hosts: frozenset[str]


def create_server(
    host: str = "127.0.0.1",
    port: int = 8765,
    allowed_hosts: Iterable[str] | None = None,
) -> SubnetkitHTTPServer:
    """Create the HTTP server with a Host-header allowlist attached."""
    httpd = SubnetkitHTTPServer((host, port), Handler)
    httpd.allowed_hosts = _allowed_hosts(host, allowed_hosts)
    return httpd


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    try:
        httpd = create_server(host, port)
    except OSError as exc:
        print(f"error: cannot start server on {host}:{port}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    actual_port = httpd.server_address[1]
    if host in ("127.0.0.1", "0.0.0.0", "::"):
        display_host = "localhost"
    elif ":" in host and not host.startswith("["):
        display_host = f"[{host}]"
    else:
        display_host = host
    url = f"http://{display_host}:{actual_port}/"
    print()
    print(f"  subnetkit web UI  →  {url}")
    print("  press Ctrl+C to stop")
    print()
    if open_browser:
        timer = threading.Timer(0.4, lambda: _open(url))
        timer.daemon = True
        timer.start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        httpd.server_close()


def _open(url: str) -> None:
    with contextlib.suppress(Exception):
        webbrowser.open(url)
