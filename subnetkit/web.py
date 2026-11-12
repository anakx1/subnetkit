"""Local web UI and JSON API for subnetkit."""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import core

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY = 1 << 20

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}


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


def _requirements(payload: dict) -> list[dict]:
    value = payload.get("requirements")
    if isinstance(value, str):
        items: list[dict] = []
        for index, line in enumerate(value.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
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
        result = []
        for index, item in enumerate(value, 1):
            if not isinstance(item, dict):
                raise core.InputError("Each requirement needs a name and hosts.")
            try:
                hosts = int(item.get("hosts", 0))
            except (TypeError, ValueError) as exc:
                raise core.InputError("Host counts must be whole numbers.") from exc
            result.append({"name": str(item.get("name") or f"subnet-{index}"), "hosts": hosts})
        return result
    raise core.InputError("Add at least one requirement.")


def _others(payload: dict) -> list[str]:
    value = payload.get("others", [])
    if isinstance(value, str):
        pieces: list[str] = []
        for line in value.splitlines():
            pieces.extend(part.strip() for part in line.split(",") if part.strip())
        return pieces
    if isinstance(value, list):
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
    return core.vlsm(_str(payload, "target"), _requirements(payload))


def api_check(payload: dict):
    return core.check_relations(_str(payload, "target"), _others(payload))


ROUTES = {
    "/api/inspect": api_inspect,
    "/api/split": api_split,
    "/api/summarize": api_summarize,
    "/api/mask": api_mask,
    "/api/vlsm": api_vlsm,
    "/api/check": api_check,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "subnetkit/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # keep the terminal calm
        pass

    def _send(self, status: int, body: bytes, content_type: str, cache: str = "no-store") -> None:
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
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _serve_static(self, name: str) -> None:
        if not name or "/" in name or "\\" in name or name.startswith("."):
            self._json(404, {"ok": False, "error": "Not found."})
            return
        path = STATIC_DIR / name
        if not path.is_file():
            self._json(404, {"ok": False, "error": "Not found."})
            return
        data = path.read_bytes()
        self._send(200, data, _MIME.get(path.suffix, "application/octet-stream"))

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
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
        path = urlsplit(self.path).path
        route = ROUTES.get(path)
        if route is None:
            self._json(404, {"ok": False, "error": "Not found."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._json(400, {"ok": False, "error": "Missing or oversized request body."})
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
        except Exception as exc:  # never leak a traceback to the browser
            self._json(500, {"ok": False, "error": f"Unexpected error: {exc}"})
            return
        self._json(200, {"ok": True, "data": data})


def serve(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"error: cannot start server on {host}:{port}: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    display_host = "localhost" if host in ("127.0.0.1", "0.0.0.0", "::") else host
    url = f"http://{display_host}:{port}/"
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
    try:
        webbrowser.open(url)
    except Exception:
        pass
