#!/usr/bin/env python3
# AISTVM Linux terminal agent. Standard library only.
# Serves a persistent PTY shell and resource metrics over the Tailscale interface.
import base64
import errno
import fcntl
import hmac
import json
import os
import pty
import select
import shutil
import struct
import subprocess
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("AISTVM_TERMINAL_PORT", "8790"))
TOKEN = os.environ.get("AISTVM_TERMINAL_TOKEN", "")
LINUX_USER = os.environ.get("AISTVM_LINUX_USER", "")
WORKSPACE = os.environ.get("AISTVM_WORKSPACE", "/tmp/aistvm-workspace")
SHELL = os.environ.get("AISTVM_SHELL", "/bin/bash")
# Short, stable prompt ("aistvm$") instead of the long user@runner:path form.
PROMPT = os.environ.get("AISTVM_PROMPT", "aistvm")
MAX_INPUT = 8192
MAX_BUFFER = 262144
READ_TIMEOUT = 20.0
READ_LIMIT = 32768
DEFAULT_COLS = 80
DEFAULT_ROWS = 24
# File manager limits: text edits stay small, uploads may be larger.
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_BYTES = 48 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 48 * 1024 * 1024


def workspace_root():
    return os.path.realpath(WORKSPACE)


def safe_path(relative):
    """Resolve a client path inside the workspace; reject anything outside."""
    root = workspace_root()
    candidate = (relative or "").strip()
    while candidate.startswith("/"):
        candidate = candidate[1:]
    target = os.path.realpath(os.path.join(root, candidate))
    if target != root and not target.startswith(root + os.sep):
        raise ValueError("duong dan nam ngoai workspace")
    return target


def relative_path(target):
    root = workspace_root()
    relative = os.path.relpath(target, root)
    return "" if relative == "." else relative


def list_directory(relative):
    target = safe_path(relative)
    if not os.path.isdir(target):
        raise ValueError("khong phai thu muc")
    entries = []
    with os.scandir(target) as iterator:
        for entry in iterator:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            entries.append({
                "name": entry.name,
                "type": "dir" if entry.is_dir(follow_symlinks=False) else "file",
                "size": int(info.st_size),
                "mtime": int(info.st_mtime),
            })
    entries.sort(key=lambda item: (item["type"] != "dir", item["name"].lower()))
    return {"path": relative_path(target), "entries": entries}


def read_file(relative):
    target = safe_path(relative)
    if not os.path.isfile(target):
        raise ValueError("khong phai tep")
    size = os.path.getsize(target)
    if size > MAX_TEXT_BYTES:
        raise ValueError("tep qua lon de mo trong app")
    with open(target, "rb") as handle:
        raw = handle.read(MAX_TEXT_BYTES)
    try:
        text = raw.decode("utf-8")
        binary = False
    except UnicodeDecodeError:
        text = raw.decode("utf-8", "replace")
        binary = True
    return {
        "path": relative_path(target),
        "content": text,
        "binary": binary,
        "size": size,
    }


def _owner_ids():
    """uid/gid of the session user, so files the app creates stay editable."""
    if not LINUX_USER:
        return None
    try:
        import pwd

        record = pwd.getpwnam(LINUX_USER)
        return record.pw_uid, record.pw_gid
    except (ImportError, KeyError):
        return None


def _heal_entry(path, uid, gid):
    """Give one entry back to the session user and restore owner access.

    The agent runs as root while the shell runs as the session user. A file the
    user creates with sudo, or one written by an older agent, can end up
    root-owned with mode 0600: it still appears in "ls" but the shell dies with
    "[Errno 13] Permission denied". Re-owning it and adding the owner bits keeps
    the terminal and the file manager consistent without opening the entry to
    other users.
    """
    if os.path.islink(path):
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    changed = False
    if info.st_uid != uid or info.st_gid != gid:
        try:
            os.chown(path, uid, gid)
            changed = True
        except OSError:
            pass
    wanted = info.st_mode | (0o700 if os.path.isdir(path) else 0o600)
    if wanted != info.st_mode:
        try:
            os.chmod(path, wanted)
            changed = True
        except OSError:
            pass
    return changed


def _apply_owner(target):
    ids = _owner_ids()
    if not ids:
        return
    uid, gid = ids
    # Walk up to (but not including) the workspace root so new parent folders
    # are owned by the session user too, not root.
    root = workspace_root()
    current = target
    while True:
        _heal_entry(current, uid, gid)
        if current == root:
            break
        parent = os.path.dirname(current)
        if parent == current or not parent.startswith(root):
            break
        current = parent


def repair_workspace():
    """Heal every entry under the workspace; report how many were changed.

    Called at startup and on demand from the app so a machine that already has
    root-owned files is fixed without recreating the session.
    """
    ids = _owner_ids()
    if not ids:
        return {"fixed": 0}
    uid, gid = ids
    root = workspace_root()
    fixed = 1 if _heal_entry(root, uid, gid) else 0
    for base, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            if _heal_entry(os.path.join(base, name), uid, gid):
                fixed += 1
        for name in files:
            if _heal_entry(os.path.join(base, name), uid, gid):
                fixed += 1
    return {"fixed": fixed}


def write_file(relative, content):
    if not relative:
        raise ValueError("thieu duong dan")
    target = safe_path(relative)
    if os.path.isdir(target):
        raise ValueError("duong dan la thu muc")
    data = content.encode("utf-8")
    if len(data) > MAX_TEXT_BYTES:
        raise ValueError("noi dung qua lon")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(data)
    _apply_owner(target)
    return {"path": relative_path(target), "size": len(data)}


def upload_file(relative, payload):
    if not relative:
        raise ValueError("thieu duong dan")
    target = safe_path(relative)
    if os.path.isdir(target):
        raise ValueError("duong dan la thu muc")
    try:
        data = base64.b64decode(payload, validate=True)
    except (ValueError, TypeError):
        raise ValueError("du lieu base64 khong hop le")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("tep tai len qua lon")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as handle:
        handle.write(data)
    _apply_owner(target)
    return {"path": relative_path(target), "size": len(data)}


def download_file(relative):
    target = safe_path(relative)
    if not os.path.isfile(target):
        raise ValueError("khong phai tep")
    size = os.path.getsize(target)
    if size > MAX_DOWNLOAD_BYTES:
        raise ValueError("tep qua lon de tai ve")
    with open(target, "rb") as handle:
        raw = handle.read(MAX_DOWNLOAD_BYTES)
    return {
        "path": relative_path(target),
        "size": size,
        "data": base64.b64encode(raw).decode("ascii"),
    }


def make_directory(relative):
    if not relative:
        raise ValueError("thieu duong dan")
    target = safe_path(relative)
    os.makedirs(target, exist_ok=True)
    _apply_owner(target)
    return {"path": relative_path(target)}


def delete_entry(relative):
    if not relative:
        raise ValueError("thieu duong dan")
    target = safe_path(relative)
    if target == workspace_root():
        raise ValueError("khong the xoa thu muc goc")
    if os.path.islink(target):
        os.remove(target)
    elif os.path.isdir(target):
        shutil.rmtree(target)
    elif os.path.exists(target):
        os.remove(target)
    else:
        raise ValueError("khong tim thay")
    return {"path": relative_path(target)}


def _cpu_sample():
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        first = handle.readline().split()
    values = [int(part) for part in first[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _memory():
    total = available = 0
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
    used = total - available
    percent = (used / total * 100.0) if total > 0 else 0.0
    return used, total, percent


def metrics_payload(previous):
    idle, total = _cpu_sample()
    cpu = 0.0
    if previous is not None:
        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta > 0:
            cpu = max(0.0, min(100.0, (total_delta - idle_delta) * 100.0 / total_delta))
    used, total_mem, percent = _memory()
    with open("/proc/uptime", "r", encoding="utf-8") as handle:
        uptime = float(handle.read().split()[0])
    return (idle, total), {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(percent, 1),
        "ram_used_gb": round(used / 1073741824.0, 2),
        "ram_total_gb": round(total_mem / 1073741824.0, 2),
        "uptime_seconds": round(uptime, 1),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


class ShellSession:
    """One persistent PTY plus a bounded, offset-addressed output ring."""

    def __init__(self):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.master = None
        self.process = None
        self.buffer = bytearray()
        self.start_offset = 0
        self.total = 0
        self.reader = None
        self.stopped = False

    @property
    def running(self):
        return self.master is not None and not self.stopped

    def start(self, cols, rows):
        with self.lock:
            if self.running:
                self._resize_locked(cols, rows)
                return
            master, slave = pty.openpty()
            self._set_winsize(master, cols, rows)
            env = dict(os.environ)
            env["TERM"] = "xterm-256color"
            env["COLORTERM"] = "truecolor"
            env["LANG"] = env.get("LANG", "C.UTF-8")
            env["AISTVM_SHELL"] = SHELL
            # Run from the workspace and give the shell a clean, short prompt.
            # HOME must stay writable or interactive tools (readline history,
            # vim swap files, htop config) would fail under the runner's root.
            env["HOME"] = WORKSPACE
            env["PWD"] = WORKSPACE
            env["PS1"] = PROMPT + "\\$ "
            env["PROMPT_COMMAND"] = ""
            env["BASH_SILENCE_DEPRECATION_WARNING"] = "1"
            def _claim_controlling_terminal():
                # start_new_session makes the child a session leader, but a
                # leader still has no controlling terminal until it claims one.
                # When the agent runs as root and drops to the session user,
                # bash then cannot set its process group and prints
                # "cannot set terminal process group (-1)" and "no job control
                # in this shell" before every prompt. Claiming the PTY that is
                # already stdin fixes both and restores Ctrl-C, fg/bg and vim.
                try:
                    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                except OSError:
                    pass

            kwargs = {
                "stdin": slave,
                "stdout": slave,
                "stderr": slave,
                "cwd": WORKSPACE,
                "env": env,
                "close_fds": True,
                # A new session plus claiming the PTY as the controlling
                # terminal is what gives the shell real job control and lets
                # Ctrl-C reach the foreground process.
                "start_new_session": True,
                "preexec_fn": _claim_controlling_terminal,
            }
            if LINUX_USER:
                # The agent runs as root; hand the shell to the session user.
                kwargs["user"] = LINUX_USER
                kwargs["group"] = LINUX_USER
                kwargs["extra_groups"] = []
            try:
                process = subprocess.Popen([SHELL, "-l"], **kwargs)
            except (OSError, ValueError):
                os.close(master)
                os.close(slave)
                raise
            os.close(slave)
            self.process = process
            self.master = master
            self.buffer = bytearray()
            self.start_offset = 0
            self.total = 0
            self.stopped = False
            self.reader = threading.Thread(target=self._pump, daemon=True)
            self.reader.start()

    def _set_winsize(self, fd, cols, rows):
        packed = struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)

    def _resize_locked(self, cols, rows):
        if self.master is None:
            return
        try:
            self._set_winsize(self.master, cols, rows)
        except OSError:
            pass

    def resize(self, cols, rows):
        with self.lock:
            self._resize_locked(cols, rows)

    def write(self, data):
        with self.lock:
            if not self.running:
                return False
            try:
                os.write(self.master, data)
                return True
            except OSError:
                return False

    def _pump(self):
        master = self.master
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 0.5)
            except (OSError, ValueError):
                break
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    break
                if not chunk:
                    break
                with self.lock:
                    self.buffer.extend(chunk)
                    self.total += len(chunk)
                    overflow = len(self.buffer) - MAX_BUFFER
                    if overflow > 0:
                        del self.buffer[:overflow]
                        self.start_offset += overflow
                    self.condition.notify_all()
            if self.stopped:
                break
        with self.lock:
            self.stopped = True
            self.condition.notify_all()

    def read(self, offset):
        with self.lock:
            if offset < self.start_offset:
                offset = self.start_offset
            index = offset - self.start_offset
            if index < 0:
                index = 0
            deadline = time.monotonic() + READ_TIMEOUT
            while index >= len(self.buffer) and not self.stopped:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)
            data = bytes(self.buffer[index:index + READ_LIMIT])
            return {
                "data": base64.b64encode(data).decode("ascii"),
                "offset": offset + len(data),
                "start_offset": self.start_offset,
                "running": self.running,
            }

    def close(self):
        with self.lock:
            self.stopped = True
            process = self.process
            self.process = None
            master = self.master
            self.master = None
            self.condition.notify_all()
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except Exception:
                pass

    def status(self):
        with self.lock:
            return {
                "running": self.running,
                "offset": self.total,
                "start_offset": self.start_offset,
            }


SESSION = ShellSession()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last_sample = None

    def log_message(self, *args):
        # Never write request lines or headers: the token travels in a header.
        return

    def _authorized(self):
        if not TOKEN:
            # Without a configured token nothing is authorized.
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].strip(), TOKEN)

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_INPUT * 8:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _query(self, name, default):
        if "?" not in self.path:
            return default
        from urllib.parse import parse_qs, urlparse

        values = parse_qs(urlparse(self.path).query).get(name)
        if not values:
            return default
        try:
            return int(values[0])
        except ValueError:
            return default

    def _query_str(self, name, default=""):
        if "?" not in self.path:
            return default
        from urllib.parse import parse_qs, urlparse

        values = parse_qs(urlparse(self.path).query).get(name)
        if not values:
            return default
        return values[0]

    def _path(self):
        return self.path.split("?", 1)[0]

    def do_GET(self):
        path = self._path()
        if path == "/health":
            self._send(200, {"ok": True})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/metrics":
            sample, payload = metrics_payload(Handler.last_sample)
            Handler.last_sample = sample
            self._send(200, payload)
            return
        if path == "/shell/read":
            offset = max(0, self._query("offset", 0))
            self._send(200, SESSION.read(offset))
            return
        if path == "/shell/status":
            self._send(200, SESSION.status())
            return
        if path == "/files/list":
            self._file_call(list_directory, self._query_str("path", ""))
            return
        if path == "/files/read":
            self._file_call(read_file, self._query_str("path", ""))
            return
        if path == "/files/download":
            self._file_call(download_file, self._query_str("path", ""))
            return
        self._send(404, {"error": "not found"})

    def _file_call(self, action, *args):
        try:
            self._send(200, action(*args))
        except ValueError as error:
            self._send(400, {"error": str(error)})
        except OSError as error:
            self._send(500, {"error": "loi he thong tep: " + str(error)})

    def do_POST(self):
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        path = self._path()
        if path == "/shell/open":
            body = self._read_json() or {}
            cols = body.get("cols", DEFAULT_COLS)
            rows = body.get("rows", DEFAULT_ROWS)
            if not isinstance(cols, int) or not 2 <= cols <= 1000:
                cols = DEFAULT_COLS
            if not isinstance(rows, int) or not 1 <= rows <= 1000:
                rows = DEFAULT_ROWS
            SESSION.start(cols, rows)
            self._send(200, SESSION.status())
            return
        if path == "/shell/input":
            body = self._read_json()
            if not body or not isinstance(body.get("data"), str):
                self._send(400, {"error": "invalid body"})
                return
            try:
                raw = base64.b64decode(body["data"], validate=True)
            except (ValueError, TypeError):
                self._send(400, {"error": "invalid base64"})
                return
            if len(raw) > MAX_INPUT:
                self._send(400, {"error": "input too large"})
                return
            ok = SESSION.write(raw)
            self._send(200, {"ok": ok, "running": SESSION.running})
            return
        if path == "/shell/resize":
            body = self._read_json() or {}
            cols = body.get("cols")
            rows = body.get("rows")
            if isinstance(cols, int) and isinstance(rows, int):
                SESSION.resize(cols, rows)
            self._send(200, SESSION.status())
            return
        if path == "/shell/close":
            SESSION.close()
            self._send(200, SESSION.status())
            return
        if path == "/files/repair":
            self._file_call(repair_workspace)
            return
        if path in ("/files/write", "/files/upload", "/files/mkdir", "/files/delete"):
            body = self._read_json()
            if not isinstance(body, dict):
                self._send(400, {"error": "invalid body"})
                return
            target = body.get("path", "")
            if not isinstance(target, str):
                self._send(400, {"error": "invalid path"})
                return
            if path == "/files/write":
                content = body.get("content")
                if not isinstance(content, str):
                    self._send(400, {"error": "invalid content"})
                    return
                self._file_call(write_file, target, content)
                return
            if path == "/files/upload":
                data = body.get("data")
                if not isinstance(data, str):
                    self._send(400, {"error": "invalid data"})
                    return
                self._file_call(upload_file, target, data)
                return
            if path == "/files/mkdir":
                self._file_call(make_directory, target)
                return
            self._file_call(delete_entry, target)
            return
        self._send(404, {"error": "not found"})


def main():
    os.makedirs(WORKSPACE, exist_ok=True)
    _apply_owner(WORKSPACE)
    repair_workspace()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("AISTVM terminal agent listening on port " + str(PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SESSION.close()


if __name__ == "__main__":
    main()
