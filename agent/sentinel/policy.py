"""Local cache of the server-managed policy (protection continues while offline)."""
import json, threading, time
from . import settings

class Policy:
    DEFAULT = {"blocked_applications": [], "protected_folders": [], "watch_processes": [], "monitoring_enabled": True,
               "secure_mode": False, "heartbeat_interval": 30, "event_categories": {}, "settings_version": 0}
    def __init__(self, path=None):
        self.path, self.lock = path or settings.POLICY_PATH, threading.RLock()
        self.data = dict(self.DEFAULT); self.force_secure = False; self.restrictions = []; self.folders_rev = 0
        try:
            with open(self.path, "r", encoding="utf-8") as f: self.data.update(json.load(f))
        except Exception: pass

    def apply(self, s: dict):
        with self.lock:
            if sorted(s.get("protected_folders", [])) != sorted(self.data.get("protected_folders", [])): self.folders_rev += 1
            for k in self.DEFAULT:
                if k in s: self.data[k] = s[k]
            try: settings.atomic_write(self.path, json.dumps(self.data).encode())
            except OSError: pass

    @property
    def version(self): return self.data.get("settings_version", 0)
    @property
    def monitoring_enabled(self): return bool(self.data.get("monitoring_enabled", True))
    @property
    def secure_mode(self): return bool(self.data.get("secure_mode")) or self.force_secure
    @property
    def heartbeat_interval(self): return int(self.data.get("heartbeat_interval", 30))
    @property
    def protected_folders(self): return list(self.data.get("protected_folders", []))
    @property
    def watch_processes(self): return {x.lower() for x in self.data.get("watch_processes", [])}

    def set_secure(self, on: bool):
        with self.lock:
            self.data["secure_mode"] = on
            if not on: self.force_secure = False
            try: settings.atomic_write(self.path, json.dumps(self.data).encode())
            except OSError: pass

    def category_enabled(self, cat) -> bool:
        return self.data.get("event_categories", {}).get(cat, True) is not False

    def blocked(self) -> set:
        now = time.time()
        with self.lock:
            self.restrictions = [(a, u) for a, u in self.restrictions if u > now]
            s = {x.lower() for x in self.data.get("blocked_applications", [])} if self.secure_mode else set()
            for a, _ in self.restrictions: s |= a
            return s

    def add_restriction(self, apps, minutes):
        with self.lock: self.restrictions.append(({a.lower() for a in apps}, time.time() + minutes * 60))
