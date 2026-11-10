"""Command-line: register / install / start / stop / remove / status / run-foreground."""
import argparse, getpass, os, platform, socket, subprocess, sys
from . import api, protect, settings
from .version import __version__

def cmd_register(a):
    url = (a.server_url or input("Functions URL (https://<ref>.supabase.co/functions/v1): ")).strip()
    name = (a.name or input(f"Device name [{socket.gethostname()}]: ").strip() or socket.gethostname())
    token = (a.token or getpass.getpass("One-time enrollment token: ")).strip()
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

def cmd_install(a):
    s = _need_service(); import win32serviceutil
    from . import service
    settings.load_config(); protect.load_secret()          # refuse to install an unregistered agent
    win32serviceutil.HandleCommandLine(s.SentinelService, argv=[sys.argv[0], "--startup", "delayed", "install"])
    service.configure_recovery(); protect.lock_down(settings.DATA_DIR)
    print("Service installed with crash recovery (3 restarts then stop). Start it: sentinel-agent start")

def cmd_service(a):
    s = _need_service(); import win32serviceutil
    win32serviceutil.HandleCommandLine(s.SentinelService, argv=[sys.argv[0], a.cmd])

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
    r = sp.add_parser("register"); r.add_argument("--server-url"); r.add_argument("--name"); r.add_argument("--token"); r.set_defaults(f=cmd_register)
    sp.add_parser("install").set_defaults(f=cmd_install)
    for c in ("start", "stop", "restart", "remove"):
        x = sp.add_parser(c); x.set_defaults(f=cmd_service, cmd=c)
    sp.add_parser("status").set_defaults(f=cmd_status); sp.add_parser("run").set_defaults(f=cmd_run)
    a = p.parse_args(argv); a.f(a)

if __name__ == "__main__": main()
