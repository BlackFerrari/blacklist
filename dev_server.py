"""Local development server and API proxy for Blacklist IP Manager.

Serves local static files (index.html, blacklist.txt, etc.) on http://localhost:8080
and handles API operations (list, add, edit, delete, bulk import/export, feeds, user-ips)
directly against local repository files, eliminating network timeouts and proxy errors.
"""

from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ipaddress
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


def valid_ip(val: str) -> bool:
    """Validates IPv4 or IPv6 address."""
    if not isinstance(val, str):
        return False
    s = val.strip()
    if not s or len(s) > 45 or any(c.isspace() for c in s):
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


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
        if self.path == "/health":
            self._send_json({"ok": True}, 200)
            return
        if self.path == "/api/feeds":
            self._handle_get_feeds()
            return
        if self.path == "/api/user-ips":
            self._handle_get_user_ips()
            return
        if self.path == "/api/list":
            self._handle_get_list()
            return
        if self.path.startswith("/api/"):
            self._proxy_request("GET")
            return
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/feeds":
            self._handle_save_feeds()
            return
        if self.path == "/api/user-ips":
            self._handle_save_user_ips()
            return
        if self.path == "/api/feeds/sync":
            self._handle_sync_feeds()
            return
        if self.path == "/api/change":
            self._handle_change()
            return
        if self.path == "/api/login":
            self._handle_login()
            return
        if self.path.startswith("/api/") or self.path == "/health":
            self._proxy_request("POST")
            return
        self.send_error(405, "Method Not Allowed")

    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json(self, data, status: int = 200):
        resp = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(resp)

    def _handle_get_list(self):
        blacklist_file = DIRECTORY / "blacklist.txt"
        user_ips_file = DIRECTORY / "user-ips.json"
        ips = []
        if blacklist_file.exists():
            for line in blacklist_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    ips.append(s)
        user_ips = {}
        if user_ips_file.exists():
            try:
                user_ips = json.loads(user_ips_file.read_text(encoding="utf-8"))
            except Exception:
                user_ips = {}
        self._send_json({"ips": ips, "user_ips": user_ips}, 200)

    def _handle_get_user_ips(self):
        user_ips_file = DIRECTORY / "user-ips.json"
        user_ips = {}
        if user_ips_file.exists():
            try:
                user_ips = json.loads(user_ips_file.read_text(encoding="utf-8"))
            except Exception:
                user_ips = {}
        self._send_json(user_ips, 200)

    def _handle_save_user_ips(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        user_ips_file = DIRECTORY / "user-ips.json"
        try:
            parsed = json.loads(body.decode("utf-8"))
            user_ips_file.write_text(json.dumps(parsed, indent=2), encoding="utf-8")
            self._send_json({"success": True, "user_ips": parsed}, 200)
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_get_feeds(self):
        feeds_file = DIRECTORY / "feeds.json"
        feeds_data = []
        if feeds_file.exists():
            try:
                feeds_data = json.loads(feeds_file.read_text(encoding="utf-8"))
            except Exception:
                feeds_data = []
        self._send_json(feeds_data, 200)

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
            self._send_json({"success": True, "feeds": feeds_list}, 200)
        except Exception as e:
            self._send_json({"error": str(e)}, 400)

    def _handle_sync_feeds(self):
        from sync_threat_intel import sync_all_feeds
        try:
            result = sync_all_feeds()
            status = 200 if result.get("success") else 500
            self._send_json(result, status)
        except Exception as e:
            self._send_json({"success": False, "error": str(e)}, 500)

    def _handle_login(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            target_url = f"{BACKEND_URL}/api/login"
            req = urllib.request.Request(
                target_url,
                data=body,
                headers={
                    "Origin": ALLOWED_ORIGIN,
                    "User-Agent": "Mozilla/5.0 BlacklistDevServer/1.0",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as res:
                resp_data = json.loads(res.read().decode("utf-8"))
                self._send_json(resp_data, res.getcode())
                return
        except urllib.error.HTTPError as err:
            try:
                resp_data = json.loads(err.read().decode("utf-8"))
            except Exception:
                resp_data = {"error": "Invalid credentials."}
            self._send_json(resp_data, err.code)
            return
        except Exception:
            # Remote worker unreachable or timed out: provide local session token
            self._send_json({"token": "dev-token-local", "expiresIn": 7200}, 200)

    def _handle_change(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json({"error": "Invalid JSON payload."}, 400)
            return

        action = payload.get("action")
        if action not in ("add", "edit", "delete", "bulk_add", "bulk_delete"):
            self._send_json({"error": "Invalid request."}, 400)
            return

        ip = (payload.get("ip") or "").strip()
        old_ip = (payload.get("oldIp") or "").strip()

        if action in ("add", "edit", "delete") and not valid_ip(ip):
            self._send_json({"error": "Enter a valid IPv4 or IPv6 address."}, 400)
            return

        if action == "edit" and not valid_ip(old_ip):
            self._send_json({"error": "Invalid original IP address."}, 400)
            return

        blacklist_file = DIRECTORY / "blacklist.txt"
        current_ips = []
        if blacklist_file.exists():
            for line in blacklist_file.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    current_ips.append(s)

        keys_lower = [x.lower() for x in current_ips]

        user_ips_file = DIRECTORY / "user-ips.json"
        user_ips = {}
        if user_ips_file.exists():
            try:
                user_ips = json.loads(user_ips_file.read_text(encoding="utf-8"))
            except Exception:
                user_ips = {}

        dates_file = DIRECTORY / "blacklist-dates.json"
        dates = {}
        if dates_file.exists():
            try:
                dates = json.loads(dates_file.read_text(encoding="utf-8"))
            except Exception:
                dates = {}

        today = datetime.now().strftime("%Y-%m-%d")
        date_val = payload.get("date") or today
        remark_val = (payload.get("remark") or "").strip() or "Manual entry"

        if action == "add":
            if ip.lower() in keys_lower:
                self._send_json({"error": "That IP is already in the blacklist."}, 409)
                return
            current_ips.append(ip)
            dates[ip] = date_val
            user_ips[ip] = {
                "date": date_val,
                "remark": remark_val,
                "source": "manual",
            }
            msg = "IP added successfully."

        elif action == "delete":
            try:
                idx = keys_lower.index(ip.lower())
            except ValueError:
                self._send_json({"error": "That IP was not found. Refresh the list."}, 404)
                return
            actual_ip = current_ips.pop(idx)
            keys_lower.pop(idx)
            dates.pop(actual_ip, None)
            dates.pop(ip, None)
            dates.pop(ip.lower(), None)
            user_ips.pop(actual_ip, None)
            user_ips.pop(ip, None)
            user_ips.pop(ip.lower(), None)
            msg = "IP deleted successfully."

        elif action == "edit":
            try:
                idx = keys_lower.index(old_ip.lower())
            except ValueError:
                self._send_json({"error": "Original IP was not found. Refresh the list."}, 404)
                return
            dup_idx = keys_lower.index(ip.lower()) if ip.lower() in keys_lower else -1
            if dup_idx >= 0 and dup_idx != idx:
                self._send_json({"error": "Replacement IP is already in the blacklist."}, 409)
                return
            actual_old = current_ips[idx]
            current_ips[idx] = ip
            old_meta = user_ips.pop(actual_old, None) or user_ips.pop(old_ip, None) or user_ips.pop(old_ip.lower(), None)
            dates.pop(actual_old, None)
            dates.pop(old_ip, None)
            dates.pop(old_ip.lower(), None)
            dates[ip] = date_val
            prior_remark = (old_meta.get("remark") if isinstance(old_meta, dict) else "") or "Manual entry"
            user_ips[ip] = {
                "date": date_val,
                "remark": (payload.get("remark") or "").strip() or prior_remark,
                "source": (old_meta.get("source") if isinstance(old_meta, dict) and old_meta.get("source") else "manual"),
            }
            msg = "IP updated successfully."

        elif action == "bulk_add":
            bulk_items = payload.get("items")
            def_remark = (payload.get("remark") or "").strip() or "Bulk import"
            to_add_list = []
            if isinstance(bulk_items, list) and bulk_items:
                for itm in bulk_items:
                    if isinstance(itm, dict):
                        b_ip = (itm.get("ip") or "").strip()
                        b_date = itm.get("date") or today
                        b_rem = (itm.get("remark") or "").strip() or def_remark
                    else:
                        b_ip = str(itm).strip()
                        b_date = today
                        b_rem = def_remark
                    if valid_ip(b_ip):
                        to_add_list.append((b_ip, b_date, b_rem))
            else:
                for itm in (payload.get("ips") or []):
                    b_ip = str(itm).strip()
                    if valid_ip(b_ip):
                        to_add_list.append((b_ip, today, def_remark))

            if not to_add_list:
                self._send_json({"error": "No valid IP addresses provided to add."}, 400)
                return

            count = 0
            for b_ip, b_date, b_rem in to_add_list:
                if b_ip.lower() not in keys_lower:
                    current_ips.append(b_ip)
                    keys_lower.append(b_ip.lower())
                    dates[b_ip] = b_date
                    user_ips[b_ip] = {
                        "date": b_date,
                        "remark": b_rem,
                        "source": "bulk",
                    }
                    count += 1

            if count == 0:
                self._send_json({
                    "error": "All provided IPs are already in the blacklist.",
                    "ips": current_ips,
                    "user_ips": user_ips,
                }, 409)
                return
            msg = f"{count} IP(s) added successfully."

        elif action == "bulk_delete":
            raw_ips = payload.get("ips") or []
            to_remove = set(str(x).strip().lower() for x in raw_ips if str(x).strip())
            if not to_remove:
                self._send_json({"error": "No valid IP addresses provided to remove."}, 400)
                return

            before_len = len(current_ips)
            new_current = []
            for item in current_ips:
                if item.lower() in to_remove:
                    dates.pop(item, None)
                    dates.pop(item.lower(), None)
                    user_ips.pop(item, None)
                    user_ips.pop(item.lower(), None)
                else:
                    new_current.append(item)
            current_ips = new_current
            removed = before_len - len(current_ips)
            if removed == 0:
                self._send_json({
                    "error": "None of the provided IPs were found in the blacklist.",
                    "ips": current_ips,
                    "user_ips": user_ips,
                }, 404)
                return
            msg = f"{removed} IP(s) removed successfully."

        # Save to disk
        blacklist_file.write_text("\n".join(current_ips) + ("\n" if current_ips else ""), encoding="utf-8")
        dates_file.write_text(json.dumps(dates, indent=2), encoding="utf-8")
        user_ips_file.write_text(json.dumps(user_ips, indent=2), encoding="utf-8")

        self._send_json({
            "message": msg,
            "ips": current_ips,
            "user_ips": user_ips,
        }, 200)

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
            with urllib.request.urlopen(req, timeout=15) as res:
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


def start_auto_scheduler(interval_seconds: int = 300):
    import threading, time
    def loop():
        while True:
            time.sleep(interval_seconds)  # Check every 5 minutes (300 seconds)
            try:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Auto-Sync Scheduler] Starting 5-minute automated threat intel sync...")
                from sync_threat_intel import sync_all_feeds
                res = sync_all_feeds()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Auto-Sync Scheduler] Completed. Total IPs in blacklist.txt: {res.get('totalIps', 0)}.")
            except Exception as err:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [Auto-Sync Scheduler] Error: {err}")
    t = threading.Thread(target=loop, daemon=True)
    t.start()


def main():
    os.chdir(DIRECTORY)
    url = f"http://localhost:{PORT}"

    if is_port_in_use(PORT):
        print("============================================================")
        print(" Blacklist IP Manager - Local Dev Server")
        print(f" Dev server is already active on {url}")
        print(f" Serving: {DIRECTORY}")
        print("============================================================")
        sys.stdout.flush()
        return

    start_auto_scheduler(300)
    server = HTTPServer(("127.0.0.1", PORT), DevHandler)
    print("============================================================")
    print(" Blacklist IP Manager - Local Dev Server")
    print(f" Serving: {DIRECTORY}")
    print(f" Local URL: {url}")
    print(f" Proxying API to: {BACKEND_URL}")
    print(" Press Ctrl+C to stop.")
    print("============================================================")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dev server...")
        server.server_close()


if __name__ == "__main__":
    main()
