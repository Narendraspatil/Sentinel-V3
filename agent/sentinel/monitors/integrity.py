"""Tamper detection. Local checks produce events; the TRUSTED comparison happens server-side
(release manifest + first-seen baselines), so an attacker who edits both file and local hash is still caught
unless they also forge what the server receives (which needs the device secret)."""
import hashlib, logging, os, re, subprocess, sys, time
from .. import settings
from .common import CREATE_NO_WINDOW
log = logging.getLogger("sentinel.integrity")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def agent_files():
    """Files whose hashes are reported: the frozen exe, or the python package files."""
    if getattr(sys, "frozen", False): return {os.path.basename(sys.executable): sys.executable}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = {}
    for d, _, fs in os.walk(root):
        for f in fs:
            if f.endswith(".py"): out[os.path.relpath(os.path.join(d, f), os.path.dirname(root)).replace("\\", "/")] = os.path.join(d, f)
    for f in ("run_agent.py", "sentinel_service.py"):
        p = os.path.join(os.path.dirname(root), f)
        if os.path.exists(p): out[f] = p
    return out

def file_hashes():
    res = {}
    for k, p in agent_files().items():
        try: res[k] = sha256_file(p)
        except OSError: res[k] = "unreadable"
    return res

def service_info(name):
    """Parsed `sc qc` output; None if the service does not exist."""
    try:
        r = subprocess.run(["sc", "qc", name], capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW)
    except Exception: return {"error": "sc_failed"}
    if r.returncode != 0: return None if "1060" in r.stdout + r.stderr else {"error": "sc_error"}
    g = lambda k: (re.search(rf"{k}\s*:\s*(.*)", r.stdout) or [None, ""])[1].strip()
    return {"start": g("START_TYPE"), "path": g("BINARY_PATH_NAME"), "account": g("SERVICE_START_NAME")}

def service_fingerprint(info):
    if not info or "error" in info: return None
    return hashlib.sha256(f"{info['start']}|{info['path']}|{info['account']}".encode()).hexdigest()

class IntegrityMonitor:
    name = "integrity"
    def __init__(self, ctx): self.ctx, self.last_hashes, self.last_svc = ctx, None, None
    def interval(self): return self.ctx.cfg["integrity_interval"]
    def run_once(self):
        em, cfg, bucket = self.ctx.emitter, self.ctx.cfg, int(time.time() // 3600)
        hs = file_hashes()
        if self.last_hashes is not None and hs != self.last_hashes:
            changed = [k for k in hs if self.last_hashes.get(k) != hs[k]]
            em.emit("agent_files_changed", "integrity", "critical", f"Agent files changed while running: {', '.join(changed[:5])}", {"files": changed[:20]}, f"files-{hash(tuple(sorted(hs.items())))}")
        self.last_hashes = hs; self.ctx.file_hashes = hs
        try:
            fresh = settings.load_config()
            fp = settings.config_fingerprint(fresh)
            if fp != self.ctx.config_fp:
                em.emit("config_tampered", "integrity", "critical", "Agent config (server URL / device id / service name) differs from the one loaded at start", {"check": "config_fingerprint"}, f"cfg-{fp[:12]}")
        except settings.ConfigError as e:
            em.emit("config_unreadable", "integrity", "critical", f"Agent configuration is missing or corrupt: {e}", {"check": "config"}, f"cfgbad-{bucket}")
        try: from .. import protect; protect.load_secret()
        except settings.ConfigError as e:
            em.emit("credentials_unreadable", "integrity", "critical", f"Device credential store unreadable: {e}", {"check": "credentials"}, f"credbad-{bucket}")
        if os.name == "nt":
            info = service_info(cfg["service_name"])
            if info is None: em.emit("service_missing", "service", "critical", "Sentinel service registration was removed", {"check": "service"}, f"svcgone-{bucket}")
            elif "error" not in info:
                self.ctx.service_fp = service_fingerprint(info)
                if self.last_svc and self.last_svc != info:
                    em.emit("service_config_changed", "service", "high", "Sentinel service configuration changed", {"previous": self.last_svc, "current": info, "check": "service_config"}, f"svccfg-{self.ctx.service_fp[:12]}")
                self.last_svc = info
        for m in self.ctx.monitors:
            if hasattr(m, "healthy") and not m.healthy(): em.emit("monitor_unhealthy", "agent", "high", f"Monitor '{m.name}' is not operating", {"monitor": m.name}, f"mon-{m.name}-{bucket}")
        dropped = self.ctx.buffer.take_dropped()
        if dropped: em.emit("buffer_dropped", "agent", "high", f"Offline buffer full: {dropped} low/medium events dropped", {"dropped": dropped})
        s = self.ctx.buffer.stats()
        if s["pct"] >= 80: em.emit("buffer_near_limit", "agent", "high" if s["pct"] >= 95 else "medium", f"Offline buffer {s['pct']}% full ({s['rows']} events)", dedup_id=f"buf-{int(s['pct']//10)}-{bucket}")
