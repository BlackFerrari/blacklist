"""Local development server and API proxy for Blacklist IP Manager.

Serves local static files (index.html, blacklist.txt, etc.) on http://localhost:8080
and proxies API calls to the Cloudflare Worker backend with the required Origin
header so you can edit and test locally in your browser without CORS errors.
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
import webbrowser

PORT = 8080
BACKEND_URL = "https://blacklist-manager-api.ranjanakasun.workers.dev"
ALLOWED_ORIGIN = "https://uptime97.github.io"
DIRECTORY = Path(__file__).resolve().parent


class DevHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIRECTORY), **kwargs)

    def end_headers(self):
        # Enable no-cache during local development so edits are immediately visible on refresh
        if self.path == "/" or self.path.endswith(".html") or self.path.endswith(".js") or self.path.endswith(".json"):
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        super().end_headers()

    def do_OPTIONS(self):
        if self.path.startswith("/api/") or self.path == "/health":
            self.send_response(204)
            self._send_cors_headers()
            self.end_headers()
            return
        super().do_OPTIONS()

    def do_GET(self):
        if self.path == "/api/feeds":
            self._handle_get_feeds()
            return
        if self.path == "/api/list":
            self._handle_get_list()
            return
        if self.path.startswith("/api/") or self.path == "/health":
            self._proxy_request("GET")
            return
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/feeds":
            self._handle_save_feeds()
            return
        if self.path == "/api/feeds/sync":
            self._handle_sync_feeds()
            return
        if self.path.startswith("/api/") or self.path == "/health":
            self._proxy_request("POST")
            return
        self.send_error(405, "Method Not Allowed")

    def _handle_get_list(self):
        blacklist_file = DIRECTORY / "blacklist.txt"
        ips = []
        if blacklist_file.exists():
            for line in blacklist_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    ips.append(s)
        resp = json.dumps({"ips": ips}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(resp)

    def _handle_get_feeds(self):
        feeds_file = DIRECTORY / "feeds.json"
        data = b"[]"
        if feeds_file.exists():
            data = feeds_file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(data)

    def _handle_save_feeds(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"[]"
        feeds_file = DIRECTORY / "feeds.json"
        try:
            parsed = json.loads(body.decode("utf-8"))
            if isinstance(parsed, dict) and "feeds" in parsed:
                feeds_list = parsed["feeds"]
            elif isinstance(parsed, list):
                feeds_list = parsed
            else:
                feeds_list = []
            feeds_file.write_text(json.dumps(feeds_list, indent=2), encoding="utf-8")
            resp = json.dumps({"success": True, "feeds": feeds_list}).encode("utf-8")
            status = 200
        except Exception as e:
            resp = json.dumps({"error": str(e)}).encode("utf-8")
            status = 400
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(resp)

    def _handle_sync_feeds(self):
        from sync_threat_intel import sync_all_feeds
        try:
            result = sync_all_feeds()
            status = 200 if result.get("success") else 500
            resp = json.dumps(result).encode("utf-8")
        except Exception as e:
            status = 500
            resp = json.dumps({"success": False, "error": str(e)}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(resp)

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _proxy_request(self, method: str):
        target_url = f"{BACKEND_URL}{self.path}"

        body = None
        if method == "POST":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body = self.rfile.read(content_length)

        headers = {
            "Origin": ALLOWED_ORIGIN,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BlacklistDevServer/1.0",
        }
        if "Content-Type" in self.headers:
            headers["Content-Type"] = self.headers["Content-Type"]
        if "Authorization" in self.headers:
            headers["Authorization"] = self.headers["Authorization"]

        req = urllib.request.Request(target_url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=60) as res:
                status = res.getcode()
                response_body = res.read()
                content_type = res.headers.get("Content-Type", "application/json; charset=utf-8")
        except urllib.error.HTTPError as err:
            status = err.code
            response_body = err.read()
            content_type = err.headers.get("Content-Type", "application/json; charset=utf-8")
        except Exception as err:
            status = 502
            response_body = json.dumps({"error": f"Dev proxy error: {str(err)}"}).encode("utf-8")
            content_type = "application/json; charset=utf-8"
        if self.path == "/api/change" and method == "POST" and 200 <= status < 300:
            try:
                import datetime
                payload = json.loads(body.decode("utf-8")) if body else {}
                action = payload.get("action")
                ip = payload.get("ip")
                dates_file = DIRECTORY / "blacklist-dates.json"
                dates = {}
                if dates_file.exists():
                    dates = json.loads(dates_file.read_text(encoding="utf-8"))
                today = datetime.datetime.now().strftime("%Y-%m-%d")
                if action == "add" and ip:
                    dates[ip] = today
                elif action == "delete" and ip:
                    dates.pop(ip, None)
                elif action == "edit" and ip:
                    old_ip = payload.get("oldIp")
                    old_date = dates.pop(old_ip, today) if old_ip else today
                    dates[ip] = old_date
                elif action == "bulk_add":
                    for item in (payload.get("ips") or []):
                        if item and item not in dates:
                            dates[item] = today
                elif action == "bulk_delete":
                    for item in (payload.get("ips") or []):
                        dates.pop(item, None)
                dates_file.write_text(json.dumps(dates, indent=2), encoding="utf-8")

                bl_file = DIRECTORY / "blacklist.txt"
                if bl_file.exists():
                    current_ips = [l.strip() for l in bl_file.read_text(encoding="utf-8").splitlines() if l.strip() and not l.strip().startswith("#")]
                    if action == "add" and ip and ip not in current_ips:
                        current_ips.append(ip)
                    elif action == "delete" and ip and ip in current_ips:
                        current_ips.remove(ip)
                    elif action == "edit" and ip:
                        old_ip = payload.get("oldIp")
                        if old_ip and old_ip in current_ips:
                            idx = current_ips.index(old_ip)
                            current_ips[idx] = ip
                    elif action == "bulk_add":
                        for itm in (payload.get("ips") or []):
                            if itm and itm not in current_ips:
                                current_ips.append(itm)
                    elif action == "bulk_delete":
                        remove_set = set(payload.get("ips") or [])
                        current_ips = [x for x in current_ips if x not in remove_set]
                    bl_file.write_text("\n".join(current_ips) + "\n", encoding="utf-8")
                    try:
                        resp_dict = json.loads(response_body.decode("utf-8"))
                        resp_dict["ips"] = current_ips
                        response_body = json.dumps(resp_dict).encode("utf-8")
                    except Exception:
                        pass
            except Exception:
                pass

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response_body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(response_body)


def is_port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def start_hourly_scheduler():
    import threading, time
    from datetime import datetime
    def loop():
        while True:
            time.sleep(3600)  # Check every 1 hour
            try:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Hourly Scheduler] Starting automated threat intel sync...")
                from sync_threat_intel import sync_all_feeds
                res = sync_all_feeds()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Hourly Scheduler] Completed. Total IPs: {res.get('totalIps', 0)}.")
            except Exception as err:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Hourly Scheduler] Error: {err}")
    t = threading.Thread(target=loop, daemon=True)
    t.start()


def main():
    os.chdir(DIRECTORY)
    url = f"http://localhost:{PORT}"

    if is_port_in_use(PORT):
        print(f"============================================================")
        print(f" Blacklist IP Manager - Local Dev Server")
        print(f" Dev server is already active on {url}")
        print(f" Serving: {DIRECTORY}")
        print(f"============================================================")
        sys.stdout.flush()
        return

    start_hourly_scheduler()
    server = HTTPServer(("127.0.0.1", PORT), DevHandler)
    print(f"============================================================")
    print(f" Blacklist IP Manager - Local Dev Server")
    print(f" Serving: {DIRECTORY}")
    print(f" Local URL: {url}")
    print(f" Proxying API to: {BACKEND_URL}")
    print(f" Press Ctrl+C to stop.")
    print(f"============================================================")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dev server...")
        server.server_close()


if __name__ == "__main__":
    main()
