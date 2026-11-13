"""Command-line: register / install / start / stop / remove / status / run-foreground."""
import argparse, base64, getpass, json, os, platform, socket, subprocess, sys, time
from . import api, protect, settings
from .version import __version__

def parse_code(code: str):
    """Install code from the dashboard: 'SNTL1.' + base64url(JSON {u: functions url, t: one-time token})."""
    code = (code or "").strip()
    try:
        if not code.startswith("SNTL1."): raise ValueError
        raw = code[6:]; d = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        u, t = d["u"], d["t"]
        if not (isinstance(u, str) and isinstance(t, str) and u and t): raise ValueError
        return u, t
    except Exception:
        raise ValueError("That install code is not valid. Copy the whole command again from the dashboard.")

def cmd_register(a):
    if a.code:
        try: url, token = parse_code(a.code)
        except ValueError as e: sys.exit(str(e))
        name = (a.name or socket.gethostname()).strip()
    else:
        url = (a.server_url or input("Functions URL (https://<ref>.supabase.co/functions/v1): ")).strip()
        name = (a.name or input(f"Device name [{socket.gethostname()}]: ").strip() or socket.gethostname())
        token = (a.token or os.environ.pop("SENTINEL_ENROLL_TOKEN", "") or getpass.getpass("One-time enrollment token: ")).strip()
    if not url.startswith("https://") and os.environ.get("SENTINEL_ALLOW_HTTP") != "1": sys.exit("server URL must start with https://")
    try:
        r = api.register(url, {"enrollment_token": token, "device_name": name, "hostname": socket.gethostname(), "os_version": platform.platform(), "agent_version": __version__})
    except api.ApiError as e: sys.exit(f"Registration failed: {e.code}")
    except Exception as e: sys.exit(f"Could not reach the server: {type(e).__name__}")
    os.makedirs(settings.DATA_DIR, exist_ok=True); protect.lock_down(settings.DATA_DIR)
    cfg = {**settings.DEFAULTS, "server_url": url.rstrip("/"), "device_id": r["device_id"], "device_name": name}
    protect.store_secret(r["device_secret"]); settings.save_config(cfg)
    if r.get("settings"):
        from .policy import Policy; Policy().apply(r["settings"])
    for p in (settings.CONFIG_PATH, settings.STATE_PATH, settings.POLICY_PATH): protect.lock_down(p) if os.path.exists(p) else None
    print(f"Registered. Device ID: {r['device_id']}\nSecret stored with Windows DPAPI in {settings.SECRET_PATH} (never shown).\nNext: sentinel-agent install   (as Administrator)")

def _need_service():
    try:
        import win32serviceutil, sentinel_service  # type: ignore
    except Exception: sys.exit("pywin32 is required (Windows only)")
    return sentinel_service

def _sc(*args):
    return subprocess.run(["sc", *args], capture_output=True, text=True, creationflags=0x08000000)

def cmd_install(a):
    from . import service
    settings.load_config(); protect.load_secret()          # refuse to install an unregistered agent
    if getattr(sys, "frozen", False):
        # Standalone .exe: register it directly with the Service Control Manager.
        r = _sc("create", settings.SERVICE_NAME, "binPath=", f'"{sys.executable}"', "start=", "delayed-auto", "obj=", "LocalSystem", "DisplayName=", settings.SERVICE_DISPLAY)
        if r.returncode == 1073: _sc("config", settings.SERVICE_NAME, "binPath=", f'"{sys.executable}"')   # already exists: repoint to this exe
        elif r.returncode != 0: sys.exit("Service install failed: " + (r.stdout + r.stderr).strip()[:300])
        _sc("description", settings.SERVICE_NAME, "Sentinel laptop security monitoring agent")
    else:
        try: import win32serviceutil, sentinel_service  # type: ignore
        except Exception: sys.exit("pywin32 is required (Windows only)")
        win32serviceutil.HandleCommandLine(sentinel_service.SentinelService, argv=[sys.argv[0], "--startup", "delayed", "install"])
    service.configure_recovery(); protect.lock_down(settings.DATA_DIR)
    print("Service installed with crash recovery (3 restarts then stop). Start it: sentinel-agent start")

def cmd_service(a):
    n = settings.SERVICE_NAME
    def stop():
        _sc("stop", n)
        for _ in range(20):
            if "STOPPED" in _sc("query", n).stdout or "1060" in _sc("query", n).stdout: break
            time.sleep(1)
    if a.cmd == "start": r = _sc("start", n)
    elif a.cmd == "stop": stop(); r = _sc("query", n)
    elif a.cmd == "restart": stop(); r = _sc("start", n)
    else: stop(); r = _sc("delete", n)                      # remove
    print((r.stdout + r.stderr).strip())
    if a.cmd in ("start", "restart") and r.returncode not in (0, 1056): sys.exit(1)

def cmd_status(a):
    from .monitors.integrity import service_info
    print("service:", service_info(settings.SERVICE_NAME)); 
    try: print("config: ok", settings.load_config()["device_id"])
    except settings.ConfigError as e: print("config: PROBLEM", e)
    try: protect.load_secret(); print("credentials: ok")
    except settings.ConfigError as e: print("credentials: PROBLEM", e)

def cmd_run(a):
    import logging, time
    from . import logging_setup; logging_setup.setup(); logging.getLogger().addHandler(logging.StreamHandler())
    from .core import Agent
    ag = Agent(); ag.start(); print("running in foreground, Ctrl+C to stop")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt: ag.shutdown()

def main(argv=None):
    p = argparse.ArgumentParser(prog="sentinel-agent"); sp = p.add_subparsers(dest="c", required=True)
    r = sp.add_parser("register"); r.add_argument("--server-url"); r.add_argument("--name"); r.add_argument("--token"); r.add_argument("--code"); r.set_defaults(f=cmd_register)
    sp.add_parser("install").set_defaults(f=cmd_install)
    for c in ("start", "stop", "restart", "remove"):
        x = sp.add_parser(c); x.set_defaults(f=cmd_service, cmd=c)
    sp.add_parser("status").set_defaults(f=cmd_status); sp.add_parser("run").set_defaults(f=cmd_run)
    a = p.parse_args(argv); a.f(a)

if __name__ == "__main__": main()
