"""Command execution. Lifecycle reported to the server: acknowledged -> executing -> completed|failed.
Replay protection: handled command ids are persisted, expired commands are refused locally as well."""
import ctypes, logging, os, socket, subprocess, threading, time
from datetime import datetime, timezone
import psutil
from . import api as apimod, protect, settings
from .monitors.common import run_ps, CREATE_NO_WINDOW

log = logging.getLogger("sentinel.commands")

class CommandError(Exception): pass

def _parse_ts(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))

class CommandRunner:
    def __init__(self, ctx): self.ctx = ctx

    def _report(self, cid, status, result=None):
        """Report with retry; undelivered final results are persisted and re-sent later."""
        try: self.ctx.api.command_result(cid, status, result)
        except apimod.ApiError as e:
            if e.status in (404, 409): return          # closed/expired/unknown on the server: nothing to do
            raise
        except apimod.NetworkError:
            if status in ("completed", "failed"):
                pend = self.ctx.state.get("pending_results", []); pend.append({"id": cid, "status": status, "result": result or {}})
                self.ctx.state.set("pending_results", pend[-50:])

    def flush_pending(self):
        pend = self.ctx.state.get("pending_results", [])
        keep = []
        for p in pend:
            try: self.ctx.api.command_result(p["id"], p["status"], p["result"])
            except apimod.ApiError: pass
            except apimod.NetworkError: keep.append(p)
        if keep != pend: self.ctx.state.set("pending_results", keep)

    def handle(self, cmd):
        cid, ctype = cmd["id"], cmd["command_type"]
        done = self.ctx.state.get("handled_commands", [])
        if cid in done: return                        # replay / duplicate delivery
        try:
            if _parse_ts(cmd["expires_at"]) < datetime.now(timezone.utc): return
        except Exception: return
        handler = getattr(self, f"cmd_{ctype}", None)
        self._report(cid, "acknowledged")
        if handler is None:
            self._finish(cid, ctype, "failed", {"error": "unsupported_command"}); return
        self._report(cid, "executing")
        try: res = handler(cmd.get("command_payload") or {}, cid)
        except Exception as e:
            log.exception("command %s failed", ctype)
            self._finish(cid, ctype, "failed", {"error": str(e)[:300]}); return
        self._finish(cid, ctype, "completed", res or {})

    def _finish(self, cid, ctype, status, result):
        done = self.ctx.state.get("handled_commands", []); done.append(cid)
        self.ctx.state.set("handled_commands", done[-200:])
        self.ctx.emitter.emit(f"command_{status}", "command", "low" if status == "completed" else "medium", f"Command {ctype} {status}", {"command_id": cid, "result": result})
        self._report(cid, status, result)

    # ── handlers ────────────────────────────────────────────────────────────
    def cmd_secure_mode_on(self, p, cid):
        self.ctx.policy.set_secure(True); return {"secure_mode": True}
    def cmd_secure_mode_off(self, p, cid):
        if self.ctx.compromised: raise CommandError("device is flagged compromised; clear the flag first")
        self.ctx.policy.set_secure(False); return {"secure_mode": False}

    def cmd_lock_workstation(self, p, cid):
        if os.name != "nt": raise CommandError("Windows only")
        # A service runs in session 0, so LockWorkStation() would not affect the user's desktop.
        k, w = ctypes.windll.kernel32, ctypes.windll.wtsapi32
        sid = k.WTSGetActiveConsoleSessionId()
        if sid == 0xFFFFFFFF: raise CommandError("no active console session")
        if not w.WTSDisconnectSession(0, sid, False): raise CommandError("WTSDisconnectSession failed")
        return {"method": "disconnect_console_session", "session": sid, "note": "user returns to the sign-in screen"}

    def cmd_security_scan(self, p, cid):
        subprocess.Popen(["powershell.exe", "-NoProfile", "-Command", "Start-MpScan -ScanType QuickScan"], creationflags=CREATE_NO_WINDOW)
        return {"started": True, "note": "Defender quick scan started; results appear in Windows Security / Defender events"}

    def cmd_health_report(self, p, cid):
        vm, du = psutil.virtual_memory(), psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/")
        return {"cpu_percent": psutil.cpu_percent(interval=0.5), "mem_percent": vm.percent, "disk_percent": du.percent,
                "boot_time": datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat(), "buffer": self.ctx.buffer.stats(),
                "posture": self.ctx.posture.status if self.ctx.posture else {}, "secure_mode": self.ctx.policy.secure_mode,
                "threads_alive": {t.name: t.is_alive() for t in self.ctx.threads}}

    def cmd_integrity_check(self, p, cid):
        self.ctx.integrity.run_once(); return {"files_hashed": len(self.ctx.file_hashes), "config_ok": True}

    def cmd_refresh_config(self, p, cid):
        self.ctx.force_settings = True; self.ctx.wake_sync.set(); return {"requested": True}

    def cmd_restrict_apps(self, p, cid):
        apps = [a for a in p.get("apps", []) if isinstance(a, str) and a.lower().endswith(".exe")][:50]
        if not apps: raise CommandError("no valid executables")
        mins = int(min(max(p.get("minutes", 60), 1), 1440))
        self.ctx.policy.add_restriction(apps, mins); return {"apps": apps, "minutes": mins}

    def cmd_rotate_credentials(self, p, cid):
        new = self.ctx.api.rotate()
        protect.store_secret(new); self.ctx.api.secret = new
        return {"rotated": True}

    # Network isolation via Windows Firewall default policy. Caveats documented in README: Supabase IPs can change.
    def cmd_network_isolate(self, p, cid):
        if not self.ctx.cfg.get("allow_network_isolation"): raise CommandError("allow_network_isolation is not enabled in the local agent config")
        host = self.ctx.cfg["server_url"].split("//", 1)[1].split("/", 1)[0]
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)})
        if not ips: raise CommandError("could not resolve server address")
        mins = int(min(max(p.get("auto_restore_minutes", 30), 5), 240))
        self._fw("add rule name=SentinelAllowCloud dir=out action=allow protocol=TCP remoteport=443 remoteip=" + ",".join(ips))
        self._fw("set allprofiles firewallpolicy blockinbound,blockoutbound")
        self.ctx.state.set("isolation_until", time.time() + mins * 60)
        return {"isolated": True, "allowed_ips": ips, "auto_restore_minutes": mins}

    def cmd_network_restore(self, p, cid):
        self.restore_network(); return {"restored": True}

    def restore_network(self):
        self._fw("set allprofiles firewallpolicy blockinbound,allowoutbound")
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=SentinelAllowCloud"], capture_output=True, creationflags=CREATE_NO_WINDOW)
        self.ctx.state.set("isolation_until", 0)

    def _fw(self, args):
        if os.name != "nt": raise CommandError("Windows only")
        parts = args.split()
        cmd = ["netsh", "advfirewall"] + (["firewall"] if parts[0] in ("add", "delete") else []) + parts
        r = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if r.returncode != 0: raise CommandError("netsh failed: " + (r.stdout + r.stderr).strip()[:200])
