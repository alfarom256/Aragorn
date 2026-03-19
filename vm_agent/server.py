#!/usr/bin/env python3
"""
VM Agent — Remote System Control Server

Runs inside a Hyper-V (or any) Windows VM, exposing system capabilities
over HTTP. Used by Aragorn's workflow tools (breakpoint_and_run, vm_exec,
vm_read_file, etc.) to coordinate kernel debugging with VM-side actions.

Endpoints:
    GET  /status          — Heartbeat (unauthenticated)
    GET  /processes       — List running processes
    GET  /files?path=...  — List directory contents
    GET  /file?path=...   — Read file (UTF-8 text or hex)
    GET  /download?path=  — Download raw binary file
    POST /upload          — Write base64-encoded file
    POST /exec            — Run process, capture output
    POST /spawn           — Start detached process
    GET  /spawned         — List tracked spawned processes
    POST /spawned/<pid>/kill — Kill a spawned process
    POST /service/create  — Create Windows driver service via SCM
    POST /service/start   — Start a driver service
    POST /service/stop    — Stop a driver service
    GET  /service/status  — Query driver service status
    POST /service/delete  — Delete (mark for deletion) a driver service
"""

import base64
import ctypes
import ctypes.wintypes
import os
import socket
import subprocess
import json
import time as _time
import winreg
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, request, jsonify
import psutil

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

app = Flask(__name__)

API_KEY = os.environ.get("VM_AGENT_API_KEY", "")
PORT = int(os.environ.get("VM_AGENT_PORT", "8080"))
HOST = os.environ.get("VM_AGENT_HOST", "0.0.0.0")
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", str(10 * 1024 * 1024)))  # 10 MB


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return jsonify({"error": "Server not configured — set VM_AGENT_API_KEY"}), 500
        key = request.headers.get("X-API-Key", "")
        if key != API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Win32 SCM constants
# ---------------------------------------------------------------------------

SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
SERVICE_TYPE_MAP = {"kernel": SERVICE_KERNEL_DRIVER, "filesystem": SERVICE_FILE_SYSTEM_DRIVER}
SERVICE_TYPE_NAMES = {v: k for k, v in SERVICE_TYPE_MAP.items()}

SERVICE_BOOT_START = 0x00000000
SERVICE_SYSTEM_START = 0x00000001
SERVICE_AUTO_START = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_DISABLED = 0x00000004
START_TYPE_MAP = {"boot": SERVICE_BOOT_START, "system": SERVICE_SYSTEM_START,
                  "auto": SERVICE_AUTO_START, "demand": SERVICE_DEMAND_START,
                  "disabled": SERVICE_DISABLED}
START_TYPE_NAMES = {v: k for k, v in START_TYPE_MAP.items()}

SERVICE_ERROR_IGNORE = 0x00000000
SERVICE_ERROR_NORMAL = 0x00000001
SERVICE_ERROR_SEVERE = 0x00000002
SERVICE_ERROR_CRITICAL = 0x00000003
ERROR_CONTROL_MAP = {"ignore": SERVICE_ERROR_IGNORE, "normal": SERVICE_ERROR_NORMAL,
                     "severe": SERVICE_ERROR_SEVERE, "critical": SERVICE_ERROR_CRITICAL}
ERROR_CONTROL_NAMES = {v: k for k, v in ERROR_CONTROL_MAP.items()}

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING = 0x00000006
SERVICE_PAUSED = 0x00000007
STATE_NAMES = {
    SERVICE_STOPPED: "STOPPED", SERVICE_START_PENDING: "START_PENDING",
    SERVICE_STOP_PENDING: "STOP_PENDING", SERVICE_RUNNING: "RUNNING",
    SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING", SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
    SERVICE_PAUSED: "PAUSED",
}

SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_QUERY_STATUS = 0x00000004
SC_STATUS_PROCESS_INFO = 0


# ---------------------------------------------------------------------------
# ctypes structures and function declarations
# ---------------------------------------------------------------------------

class SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", ctypes.wintypes.DWORD),
        ("dwCurrentState", ctypes.wintypes.DWORD),
        ("dwControlsAccepted", ctypes.wintypes.DWORD),
        ("dwWin32ExitCode", ctypes.wintypes.DWORD),
        ("dwServiceSpecificExitCode", ctypes.wintypes.DWORD),
        ("dwCheckPoint", ctypes.wintypes.DWORD),
        ("dwWaitHint", ctypes.wintypes.DWORD),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwServiceFlags", ctypes.wintypes.DWORD),
    ]

advapi32 = ctypes.windll.advapi32

advapi32.OpenSCManagerW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
advapi32.OpenSCManagerW.restype = ctypes.c_void_p

advapi32.CreateServiceW.argtypes = [
    ctypes.c_void_p, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPDWORD, ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPCWSTR,
]
advapi32.CreateServiceW.restype = ctypes.c_void_p

advapi32.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
advapi32.OpenServiceW.restype = ctypes.c_void_p

advapi32.StartServiceW.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p]
advapi32.StartServiceW.restype = ctypes.wintypes.BOOL

advapi32.ControlService.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p]
advapi32.ControlService.restype = ctypes.wintypes.BOOL

advapi32.DeleteService.argtypes = [ctypes.c_void_p]
advapi32.DeleteService.restype = ctypes.wintypes.BOOL

advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]
advapi32.CloseServiceHandle.restype = ctypes.wintypes.BOOL

advapi32.QueryServiceStatusEx.argtypes = [
    ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.c_void_p,
    ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD),
]
advapi32.QueryServiceStatusEx.restype = ctypes.wintypes.BOOL


# ---------------------------------------------------------------------------
# Win32 SCM helpers
# ---------------------------------------------------------------------------

def _win32_error(context: str) -> dict:
    code = ctypes.GetLastError()
    msg = ctypes.FormatError(code)
    print(f"[vm_agent] Win32 error in {context}: {code} — {msg}")
    return {"error": context, "win32_error_code": code, "win32_error_message": msg}

def _open_scm():
    return advapi32.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)

def _close(handle):
    if handle:
        advapi32.CloseServiceHandle(handle)

def _query_service_status(h_svc) -> dict:
    ssp = SERVICE_STATUS_PROCESS()
    needed = ctypes.wintypes.DWORD(0)
    ok = advapi32.QueryServiceStatusEx(
        h_svc, SC_STATUS_PROCESS_INFO, ctypes.byref(ssp),
        ctypes.sizeof(ssp), ctypes.byref(needed),
    )
    if not ok:
        return _win32_error("QueryServiceStatusEx")
    return {
        "state": STATE_NAMES.get(ssp.dwCurrentState, f"UNKNOWN({ssp.dwCurrentState})"),
        "service_type": SERVICE_TYPE_NAMES.get(ssp.dwServiceType, f"0x{ssp.dwServiceType:X}"),
        "win32_exit_code": ssp.dwWin32ExitCode,
        "service_specific_exit_code": ssp.dwServiceSpecificExitCode,
        "pid": ssp.dwProcessId,
    }

def _setup_minifilter_registry(service_name: str, altitude: str, instance_name: str):
    base_path = rf"SYSTEM\CurrentControlSet\Services\{service_name}"
    instances_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"{base_path}\Instances", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(instances_key, "DefaultInstance", 0, winreg.REG_SZ, instance_name)
    winreg.CloseKey(instances_key)
    inst_key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, rf"{base_path}\Instances\{instance_name}", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(inst_key, "Altitude", 0, winreg.REG_SZ, altitude)
    winreg.SetValueEx(inst_key, "Flags", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(inst_key)


# ---------------------------------------------------------------------------
# Status / heartbeat
# ---------------------------------------------------------------------------

@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "ok", "hostname": socket.gethostname(), "platform": os.name, "version": "1.0.0"})


# ---------------------------------------------------------------------------
# Process listing
# ---------------------------------------------------------------------------

@app.route("/processes", methods=["GET"])
@require_api_key
def list_processes():
    procs = []
    for proc in psutil.process_iter(["pid", "name", "status", "username", "cpu_percent", "memory_info"]):
        try:
            info = proc.info
            mem = info.get("memory_info")
            procs.append({
                "pid": info["pid"], "name": info["name"], "status": info["status"],
                "username": info["username"], "cpu_percent": info["cpu_percent"],
                "memory_mb": round(mem.rss / 1024 / 1024, 2) if mem else None,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return jsonify({"processes": procs, "count": len(procs)})


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

@app.route("/files", methods=["GET"])
@require_api_key
def list_files():
    raw = request.args.get("path", ".")
    try:
        p = Path(raw).resolve()
        if not p.exists():
            return jsonify({"error": f"Path does not exist: {p}"}), 422
        if not p.is_dir():
            return jsonify({"error": f"Not a directory: {p}"}), 400
        entries = []
        for entry in sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            try:
                stat = entry.stat()
                entries.append({"name": entry.name, "path": str(entry),
                                "type": "directory" if entry.is_dir() else "file",
                                "size": stat.st_size if entry.is_file() else None})
            except (PermissionError, OSError):
                entries.append({"name": entry.name, "path": str(entry), "error": "access denied"})
        return jsonify({"path": str(p), "entries": entries, "count": len(entries)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/download", methods=["GET"])
@require_api_key
def download_file():
    from flask import send_file as flask_send_file
    raw = request.args.get("path", "")
    if not raw:
        return jsonify({"error": "path query parameter is required"}), 400
    try:
        p = Path(raw).resolve()
        if not p.exists():
            return jsonify({"error": f"Path does not exist: {p}"}), 422
        if not p.is_file():
            return jsonify({"error": f"Not a file: {p}"}), 400
        if p.stat().st_size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too large ({p.stat().st_size} bytes, max {MAX_FILE_SIZE})"}), 413
        return flask_send_file(str(p), mimetype="application/octet-stream")
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/file", methods=["GET"])
@require_api_key
def read_file():
    raw = request.args.get("path", "")
    if not raw:
        return jsonify({"error": "path query parameter is required"}), 400
    try:
        p = Path(raw).resolve()
        if not p.exists():
            return jsonify({"error": f"Path does not exist: {p}"}), 422
        if not p.is_file():
            return jsonify({"error": f"Not a file: {p}"}), 400
        size = p.stat().st_size
        if size > MAX_FILE_SIZE:
            return jsonify({"error": f"File too large ({size} bytes, max {MAX_FILE_SIZE})"}), 413
        try:
            content = p.read_text(encoding="utf-8", errors="strict")
            encoding = "utf-8"
        except (UnicodeDecodeError, ValueError):
            content = p.read_bytes().hex()
            encoding = "hex"
        return jsonify({"path": str(p), "content": content, "encoding": encoding, "size": size})
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/upload", methods=["POST"])
@require_api_key
def upload_file():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    dest = data.get("path", "")
    if not dest:
        return jsonify({"error": "'path' field is required"}), 400
    content_b64 = data.get("content_b64", "")
    if not content_b64:
        return jsonify({"error": "'content_b64' field is required"}), 400
    overwrite = bool(data.get("overwrite", False))
    try:
        raw = base64.b64decode(content_b64, validate=True)
    except Exception:
        return jsonify({"error": "Invalid base64 in 'content_b64'"}), 400
    if len(raw) > MAX_FILE_SIZE:
        return jsonify({"error": f"Payload too large ({len(raw)} bytes, max {MAX_FILE_SIZE})"}), 413
    try:
        p = Path(dest).resolve()
        if p.exists() and not overwrite:
            return jsonify({"error": f"File already exists (set overwrite=true to replace): {p}"}), 409
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        return jsonify({"path": str(p), "size": len(raw)})
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


# ---------------------------------------------------------------------------
# Process execution
# ---------------------------------------------------------------------------

@app.route("/exec", methods=["POST"])
@require_api_key
def exec_process():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    executable = data.get("executable", "")
    if not executable:
        return jsonify({"error": "'executable' field is required"}), 400
    args = data.get("args", [])
    cwd = data.get("cwd") or None
    timeout = int(data.get("timeout", 30))
    capture = bool(data.get("capture_output", True))
    env_extra = data.get("env", {})
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    cmd = [executable] + [str(a) for a in args]
    try:
        result = subprocess.run(cmd, capture_output=capture, text=True, cwd=cwd, timeout=timeout, env=env)
        return jsonify({"returncode": result.returncode,
                        "stdout": result.stdout if capture else None,
                        "stderr": result.stderr if capture else None, "command": cmd})
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Process timed out after {timeout}s", "command": cmd}), 408
    except FileNotFoundError:
        return jsonify({"error": f"Executable not found: {executable}", "command": cmd}), 422
    except Exception as exc:
        return jsonify({"error": str(exc), "command": cmd}), 500


# ---------------------------------------------------------------------------
# Spawn + process management
# ---------------------------------------------------------------------------

_spawned = {}

@app.route("/spawn", methods=["POST"])
@require_api_key
def spawn_process():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    executable = data.get("executable", "")
    if not executable:
        return jsonify({"error": "'executable' field is required"}), 400
    args = data.get("args", [])
    cwd = data.get("cwd") or None
    env_extra = data.get("env", {})
    stdout_file = data.get("stdout_file", "")
    stderr_file = data.get("stderr_file", "")
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    cmd = [executable] + [str(a) for a in args]
    try:
        stdout_handle = open(stdout_file, "w") if stdout_file else subprocess.DEVNULL
        stderr_handle = open(stderr_file, "w") if stderr_file else subprocess.DEVNULL
        proc = subprocess.Popen(cmd, stdout=stdout_handle, stderr=stderr_handle, stdin=subprocess.DEVNULL,
                                cwd=cwd, env=env, creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
        if stdout_file and stdout_handle != subprocess.DEVNULL:
            stdout_handle.close()
        if stderr_file and stderr_handle != subprocess.DEVNULL:
            stderr_handle.close()
        _spawned[proc.pid] = {"cmd": cmd, "start_time": _time.time(), "stdout_file": stdout_file, "stderr_file": stderr_file}
        return jsonify({"pid": proc.pid, "command": cmd})
    except FileNotFoundError:
        return jsonify({"error": f"Executable not found: {executable}", "command": cmd}), 422
    except Exception as exc:
        return jsonify({"error": str(exc), "command": cmd}), 500


@app.route("/spawned", methods=["GET"])
@require_api_key
def list_spawned():
    result = []
    dead_pids = []
    for pid, info in _spawned.items():
        alive = psutil.pid_exists(pid)
        entry = {"pid": pid, "alive": alive, "cmd": info["cmd"],
                 "start_time": info["start_time"], "uptime": _time.time() - info["start_time"]}
        if alive:
            try:
                p = psutil.Process(pid)
                entry["cpu_percent"] = p.cpu_percent(interval=0)
                entry["memory_mb"] = round(p.memory_info().rss / 1048576, 1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                entry["alive"] = False
        if not entry["alive"]:
            dead_pids.append(pid)
        result.append(entry)
    cutoff = _time.time() - 300
    for pid in dead_pids:
        if _spawned[pid]["start_time"] < cutoff:
            del _spawned[pid]
    return jsonify(result)


@app.route("/spawned/<int:pid>", methods=["GET"])
@require_api_key
def get_spawned(pid):
    if pid not in _spawned:
        return jsonify({"pid": pid, "alive": psutil.pid_exists(pid), "tracked": False})
    info = _spawned[pid]
    alive = psutil.pid_exists(pid)
    result = {"pid": pid, "alive": alive, "tracked": True, **info}
    if alive:
        try:
            p = psutil.Process(pid)
            result["cpu_percent"] = p.cpu_percent(interval=0)
            result["memory_mb"] = round(p.memory_info().rss / 1048576, 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            result["alive"] = False
    return jsonify(result)


@app.route("/spawned/<int:pid>/kill", methods=["POST"])
@require_api_key
def kill_spawned(pid):
    try:
        p = psutil.Process(pid)
        p.kill()
        return jsonify({"pid": pid, "killed": True})
    except psutil.NoSuchProcess:
        return jsonify({"pid": pid, "killed": False, "error": "process not found"}), 404
    except psutil.AccessDenied:
        return jsonify({"pid": pid, "killed": False, "error": "access denied"}), 403


# ---------------------------------------------------------------------------
# Driver service management
# ---------------------------------------------------------------------------

@app.route("/service/create", methods=["POST"])
@require_api_key
def service_create():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    name = data.get("name", "")
    binary_path = data.get("binary_path", "")
    if not name or not binary_path:
        return jsonify({"error": "'name' and 'binary_path' are required"}), 400
    display_name = data.get("display_name", name)
    service_type_str = data.get("service_type", "kernel")
    start_type_str = data.get("start_type", "demand")
    error_control_str = data.get("error_control", "normal")
    load_order_group = data.get("load_order_group")
    minifilter = data.get("minifilter")
    if minifilter:
        service_type_str = "filesystem"
        if not load_order_group:
            load_order_group = "FSFilter Activity Monitor"
    service_type = SERVICE_TYPE_MAP.get(service_type_str)
    if service_type is None:
        return jsonify({"error": f"Invalid service_type '{service_type_str}', use: {list(SERVICE_TYPE_MAP)}"}), 400
    start_type = START_TYPE_MAP.get(start_type_str)
    if start_type is None:
        return jsonify({"error": f"Invalid start_type '{start_type_str}', use: {list(START_TYPE_MAP)}"}), 400
    error_control = ERROR_CONTROL_MAP.get(error_control_str)
    if error_control is None:
        return jsonify({"error": f"Invalid error_control '{error_control_str}', use: {list(ERROR_CONTROL_MAP)}"}), 400
    h_scm = _open_scm()
    if not h_scm:
        return jsonify(_win32_error("OpenSCManager")), 500
    try:
        ctypes.windll.kernel32.SetLastError(0)
        h_svc = advapi32.CreateServiceW(h_scm, name, display_name, SERVICE_ALL_ACCESS,
                                        service_type, start_type, error_control, binary_path,
                                        load_order_group, None, None, None, None)
        if not h_svc:
            return jsonify(_win32_error("CreateService")), 500
        _close(h_svc)
    finally:
        _close(h_scm)
    if minifilter:
        altitude = minifilter.get("altitude", "")
        instance_name = minifilter.get("default_instance", f"{name} Instance")
        if altitude:
            try:
                _setup_minifilter_registry(name, altitude, instance_name)
            except Exception as exc:
                return jsonify({"error": f"Service created but minifilter registry setup failed: {exc}"}), 500
    result = {"name": name, "binary_path": binary_path, "service_type": service_type_str,
              "start_type": start_type_str, "error_control": error_control_str,
              "load_order_group": load_order_group, "created": True}
    if minifilter:
        result["minifilter"] = {"altitude": altitude, "default_instance": instance_name}
    return jsonify(result)


@app.route("/service/start", methods=["POST"])
@require_api_key
def service_start():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "'name' is required"}), 400
    h_scm = _open_scm()
    if not h_scm:
        return jsonify(_win32_error("OpenSCManager")), 500
    try:
        h_svc = advapi32.OpenServiceW(h_scm, name, SERVICE_ALL_ACCESS)
        if not h_svc:
            return jsonify(_win32_error("OpenService")), 500
        try:
            ctypes.windll.kernel32.SetLastError(0)
            if not advapi32.StartServiceW(h_svc, 0, None):
                return jsonify(_win32_error("StartService")), 500
            return jsonify({"name": name, "status": _query_service_status(h_svc)})
        finally:
            _close(h_svc)
    finally:
        _close(h_scm)


@app.route("/service/stop", methods=["POST"])
@require_api_key
def service_stop():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "'name' is required"}), 400
    h_scm = _open_scm()
    if not h_scm:
        return jsonify(_win32_error("OpenSCManager")), 500
    try:
        h_svc = advapi32.OpenServiceW(h_scm, name, SERVICE_ALL_ACCESS)
        if not h_svc:
            return jsonify(_win32_error("OpenService")), 500
        try:
            ssp = SERVICE_STATUS_PROCESS()
            ctypes.windll.kernel32.SetLastError(0)
            if not advapi32.ControlService(h_svc, SERVICE_CONTROL_STOP, ctypes.byref(ssp)):
                return jsonify(_win32_error("ControlService(STOP)")), 500
            return jsonify({"name": name, "status": _query_service_status(h_svc)})
        finally:
            _close(h_svc)
    finally:
        _close(h_scm)


@app.route("/service/status", methods=["GET"])
@require_api_key
def service_status():
    name = request.args.get("name", "")
    if not name:
        return jsonify({"error": "'name' query parameter is required"}), 400
    h_scm = _open_scm()
    if not h_scm:
        return jsonify(_win32_error("OpenSCManager")), 500
    try:
        h_svc = advapi32.OpenServiceW(h_scm, name, SERVICE_QUERY_STATUS)
        if not h_svc:
            return jsonify(_win32_error("OpenService")), 500
        try:
            return jsonify({"name": name, "status": _query_service_status(h_svc)})
        finally:
            _close(h_svc)
    finally:
        _close(h_scm)


@app.route("/service/delete", methods=["POST"])
@require_api_key
def service_delete():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "'name' is required"}), 400
    h_scm = _open_scm()
    if not h_scm:
        return jsonify(_win32_error("OpenSCManager")), 500
    try:
        h_svc = advapi32.OpenServiceW(h_scm, name, SERVICE_ALL_ACCESS)
        if not h_svc:
            return jsonify(_win32_error("OpenService")), 500
        try:
            ctypes.windll.kernel32.SetLastError(0)
            if not advapi32.DeleteService(h_svc):
                return jsonify(_win32_error("DeleteService")), 500
        finally:
            _close(h_svc)
    finally:
        _close(h_scm)
    minifilter_registry = False
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}\Instances")
        winreg.CloseKey(key)
        minifilter_registry = True
    except FileNotFoundError:
        pass
    return jsonify({"name": name, "deleted": True, "minifilter_registry_present": minifilter_registry})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not API_KEY:
        print("[WARNING] VM_AGENT_API_KEY is not set — all authenticated endpoints will return 500.")
        print("          Set it before exposing this server on the network.\n")
    print(f"[vm_agent] Starting on http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
