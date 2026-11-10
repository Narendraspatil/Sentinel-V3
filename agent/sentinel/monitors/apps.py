"""Process monitor: blocks apps in Secure Mode (or under a temporary restriction), alerts on watch-list
tools and encoded PowerShell. psutil polling every few seconds, de-duplicated per process instance."""
import logging, os, time
import psutil
log = logging.getLogger("sentinel.apps")
PROTECTED_NAMES = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe"}

class AppMonitor:
    name = "apps"
    def __init__(self, ctx): self.ctx, self.seen, self.started = ctx, set(), time.time()
    def interval(self): return self.ctx.cfg["app_poll_seconds"]
    def run_once(self):
        p = self.ctx.policy
        if not p.monitoring_enabled: return
        blocked, watch = p.blocked(), p.watch_processes
        live = set()
        for pr in psutil.process_iter(["pid", "name", "create_time", "cmdline", "exe"]):
            try:
                i = pr.info; name = (i["name"] or "").lower(); key = (i["pid"], i["create_time"]); live.add(key)
                if key in self.seen: continue
                self.seen.add(key)
                if i["create_time"] < self.started - 5: continue         # ignore processes that pre-date the agent
                if name in blocked and name not in PROTECTED_NAMES:
                    ok = True
                    try: pr.kill(); pr.wait(2)
                    except Exception as e: ok = False; log.warning("kill failed %s: %s", name, e)
                    self.ctx.emitter.emit("app_blocked" if ok else "app_block_failed", "application", "high" if ok else "critical",
                        f"Blocked application {'terminated' if ok else 'could NOT be terminated'}: {name}", {"name": name, "exe": i["exe"], "secure_mode": p.secure_mode})
                elif name in watch:
                    self.ctx.emitter.emit("watchlist_process", "application", "high", f"Watch-list process started: {name}", {"name": name, "exe": i["exe"], "cmdline": " ".join(i["cmdline"] or [])[:300]})
                elif name in ("powershell.exe", "pwsh.exe") and i["cmdline"] and any(a.lower() in ("-enc", "-encodedcommand", "-e") for a in i["cmdline"]):
                    self.ctx.emitter.emit("powershell_encoded", "application", "medium", "PowerShell started with an encoded command", {"cmdline": " ".join(i["cmdline"])[:300]})
                elif name in ("taskkill.exe", "sc.exe", "net.exe", "powershell.exe") and i["cmdline"]:
                    cl = " ".join(i["cmdline"]).lower(); svc = self.ctx.cfg["service_name"].lower()
                    if svc in cl or "sentinel" in cl and ("stop" in cl or "delete" in cl or "/f" in cl):
                        self.ctx.emitter.emit("sentinel_tamper_attempt", "integrity", "critical", f"Command targeting the Sentinel service: {name}", {"cmdline": cl[:300]})
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        self.seen &= live | {k for k in self.seen if False}
