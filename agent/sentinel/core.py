"""Agent runtime: monitor threads, sync loop (heartbeat+settings+commands), upload loop (batched, ack-based)."""
import json, logging, os, platform, random, socket, threading, time
from . import api as apimod, protect, settings
from .buffer import EventBuffer
from .commands import CommandRunner
from .events import Emitter
from .monitors.apps import AppMonitor
from .monitors.files import FileMonitor
from .monitors.integrity import IntegrityMonitor, file_hashes, service_fingerprint, service_info
from .monitors.posture import PostureMonitor
from .monitors.usb import UsbMonitor
from .monitors.winlog import WinLogMonitor
from .policy import Policy
from .version import __version__

log = logging.getLogger("sentinel.core")

class Agent:
    def __init__(self):
        self.stop = threading.Event(); self.wake_upload = threading.Event(); self.wake_sync = threading.Event()
        cfg = settings.load_config(); secret = protect.load_secret()          # raises ConfigError if tampered/missing
        self.cfg, self.state, self.policy = cfg, settings.State(), Policy()
        self.buffer = EventBuffer(settings.BUFFER_PATH, cfg["buffer_max_rows"])
        self.emitter = Emitter(self.buffer, self.policy, self.wake_upload)
        self.api = apimod.DeviceAPI(cfg["server_url"], cfg["device_id"], secret)
        self.config_fp, self.service_fp, self.file_hashes = settings.config_fingerprint(cfg), None, file_hashes()
        self.compromised = False; self.force_settings = False; self.revoked = False
        self.threads, self.monitors = [], []
        self.ctx = self                                  # monitors/commands use the agent itself as their context
        self.posture = PostureMonitor(self); self.integrity = IntegrityMonitor(self)
        self.monitors = [WinLogMonitor(self), UsbMonitor(self), FileMonitor(self), AppMonitor(self), self.posture, self.integrity]
        self.runner = CommandRunner(self)

    # ── lifecycle ───────────────────────────────────────────────────────────
    def start(self):
        st = self.state
        if self.buffer.recovered: self.emitter.emit("buffer_corrupt_recovered", "agent", "high", "Offline buffer was corrupt and has been quarantined and recreated")
        if st.get("running") is True: self.emitter.emit("unclean_shutdown", "service", "high", "Agent did not shut down cleanly (crash, kill or power loss)")
        starts = [t for t in st.get("starts", []) if time.time() - t < 600] + [time.time()]
        st.update(starts=starts, running=True)
        if len(starts) >= 4: self.emitter.emit("service_crash_loop", "service", "critical", f"Agent restarted {len(starts)} times in 10 minutes")
        self.emitter.emit("agent_started", "agent", "low", f"Sentinel agent {__version__} started", {"version": __version__, "host": socket.gethostname()})
        if st.get("isolation_until", 0) and st.get("isolation_until") < time.time(): self._safe(self.runner.restore_network)
        for m in self.monitors: self._spawn(m.name, lambda m=m: self._loop(m))
        self._spawn("sync", self._sync_loop); self._spawn("upload", self._upload_loop)

    def shutdown(self):
        self.stop.set(); self.wake_sync.set(); self.wake_upload.set()
        try: self.api.sync(self._sync_payload(stopping=True))        # tell the server this was deliberate
        except Exception: pass
        self.emitter.emit("agent_stopped", "agent", "medium", "Sentinel agent stopping (service stop/shutdown)")
        try: self._upload_once()
        except Exception: pass
        self.state.set("running", False)

    def _spawn(self, name, fn):
        t = threading.Thread(target=fn, name=name, daemon=True); t.start(); self.threads.append(t)
    def _safe(self, fn):
        try: fn()
        except Exception: log.exception("error in %s", getattr(fn, "__name__", fn))

    def _loop(self, m):
        crashes = 0
        while not self.stop.is_set():
            try: m.run_once(); crashes = 0
            except Exception:
                crashes += 1; log.exception("monitor %s crashed", m.name)
                if crashes in (1, 5): self.emitter.emit("monitor_error", "agent", "medium", f"Monitor {m.name} raised an error ({crashes}x)", {"monitor": m.name}, f"monerr-{m.name}-{int(time.time()//600)}")
            self.stop.wait(min(m.interval() * (1 + min(crashes, 5)), 600) if crashes else m.interval())

    # ── sync (heartbeat + settings + commands) ──────────────────────────────
    def _sync_payload(self, stopping=False):
        return {"agent_version": __version__, "current_mode": "secure" if self.policy.secure_mode else "open", "hostname": socket.gethostname(),
                "os_version": platform.platform(), "system_status": {**(self.posture.status if self.posture else {}), "buffer": self.buffer.stats()},
                "config_fingerprint": self.config_fp, "service_fingerprint": self.service_fp, "file_hashes": self.file_hashes,
                "settings_version": -1 if self.force_settings else self.policy.version, "lifecycle": "stopping" if stopping else "running", "buffer": self.buffer.stats()}

    def _sync_loop(self):
        backoff = 0
        while not self.stop.is_set():
            try:
                r = self.api.sync(self._sync_payload()); backoff = 0; self.revoked = False
                self.force_settings = False
                if r.get("settings"): self.policy.apply(r["settings"])
                self.compromised = bool(r.get("compromised"))
                if self.compromised and not self.policy.force_secure:
                    self.policy.force_secure = True
                    self.emitter.emit("compromised_flag", "security", "critical", "Server flagged this device as compromised: Secure Mode enforced")
                if not self.compromised: self.policy.force_secure = False
                for c in r.get("commands", []): self._safe(lambda c=c: self.runner.handle(c))
                self.runner.flush_pending()
                iso = self.state.get("isolation_until", 0)
                if iso and iso < time.time(): self._safe(self.runner.restore_network)
                interval = int(r.get("heartbeat_interval") or self.policy.heartbeat_interval)
            except apimod.AuthRevoked:
                self.revoked = True; log.error("device credentials revoked by administrator"); interval = 300
            except apimod.AuthInvalid:
                log.error("server rejected device credentials"); self.emitter.emit("credentials_rejected", "integrity", "critical", "Server rejected this device's credentials", dedup_id=f"rej-{int(time.time()//3600)}"); interval = 300
            except (apimod.NetworkError, apimod.ApiError) as e:
                backoff = min(max(backoff * 2, 15), 300); interval = backoff + random.uniform(0, 5); log.info("sync failed (%s), retry in %ss", e, int(interval))
            except Exception:
                log.exception("sync loop error"); interval = 60
            self.wake_sync.wait(interval); self.wake_sync.clear()

    # ── upload (batched; local rows removed ONLY after server ack) ──────────
    def _upload_once(self):
        sent = 0
        while not self.stop.is_set() or sent == 0:
            batch = self.buffer.batch(self.cfg["batch_size"])
            if not batch: return sent
            payload = [{"dedup_id": e["dedup_id"], "event_type": e["event_type"], "category": e["category"], "severity": e["severity"], "source": e.get("source", "agent"),
                        "message": e["message"], "details": e.get("details", {}), "event_timestamp": e["event_timestamp"]} for e in batch]
            r = self.api.events(payload)
            self.buffer.ack(r.get("accepted", []))
            rej = [x["dedup_id"] for x in r.get("rejected", [])]
            if rej: log.warning("server rejected %d malformed events (dropping them)", len(rej)); self.buffer.discard(rej)
            sent += len(batch)
            if len(batch) < self.cfg["batch_size"]: return sent

    def _upload_loop(self):
        backoff = 0
        while not self.stop.is_set():
            try: self._upload_once(); backoff = 0; wait = self.cfg["upload_interval"]
            except apimod.AuthRevoked: wait = 300
            except apimod.AuthInvalid: wait = 300
            except (apimod.NetworkError, apimod.ApiError): backoff = min(max(backoff * 2, 15), 300); wait = backoff + random.uniform(0, 5)
            except Exception: log.exception("upload error"); wait = 60
            self.wake_upload.wait(wait); self.wake_upload.clear()
