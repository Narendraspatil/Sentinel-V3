"""Paths, local (non-secret) configuration and persisted agent state."""
import hashlib, json, os, sys, threading, time

DATA_DIR = os.environ.get("SENTINEL_DATA_DIR") or os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Sentinel")
def _p(n): return os.path.join(DATA_DIR, n)
CONFIG_PATH, SECRET_PATH, BUFFER_PATH = _p("config.json"), _p("secret.bin"), _p("events.db")
STATE_PATH, POLICY_PATH, LOG_DIR = _p("state.json"), _p("policy.json"), _p("logs")
SERVICE_NAME = "SentinelAgent"
SERVICE_DISPLAY = "Sentinel Security Agent"

DEFAULTS = {
    "server_url": "", "device_id": "", "device_name": "", "service_name": SERVICE_NAME,
    "upload_interval": 15, "long_poll_seconds": 25, "batch_size": 100, "buffer_max_rows": 100000,
    "usb_poll_seconds": 20, "posture_interval": 300, "integrity_interval": 300,
    "winlog_interval": 15, "app_poll_seconds": 3,
    "sysmon_enabled": False, "sysmon_event_ids": [1],
    "failed_logon_threshold": 5,
    "allow_network_isolation": False,
}

class ConfigError(Exception): pass

_self_write_until = 0.0
def mark_self_write(seconds=5.0):
    global _self_write_until; _self_write_until = time.time() + seconds
def is_self_write(): return time.time() < _self_write_until

def atomic_write(path, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    mark_self_write()
    with open(tmp, "wb") as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)

def load_config() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f: cfg = json.load(f)
    except FileNotFoundError: raise ConfigError("config.json is missing")
    except (OSError, ValueError) as e: raise ConfigError(f"config.json unreadable/corrupt: {type(e).__name__}")
    if not isinstance(cfg, dict): raise ConfigError("config.json has wrong structure")
    out = {**DEFAULTS, **cfg}
    if not out["device_id"] or not out["server_url"]: raise ConfigError("config.json missing device_id/server_url")
    if not out["server_url"].startswith("https://") and os.environ.get("SENTINEL_ALLOW_HTTP") != "1":
        raise ConfigError("server_url must be https://")
    return out

def save_config(cfg: dict):
    atomic_write(CONFIG_PATH, json.dumps(cfg, indent=2).encode())

def exe_path() -> str:
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0] if sys.argv and sys.argv[0] else __file__)

def config_fingerprint(cfg: dict) -> str:
    """Covers only STATIC identity fields so server-pushed settings never change it."""
    basis = "|".join([cfg.get("server_url", ""), cfg.get("device_id", ""), cfg.get("service_name", "")])
    return hashlib.sha256(basis.encode()).hexdigest()

class State:
    def __init__(self, path=None):
        self.path, self.lock, self.data = path or STATE_PATH, threading.RLock(), {}
        try:
            with open(self.path, "r", encoding="utf-8") as f: self.data = json.load(f)
        except Exception: self.data = {}
    def get(self, k, default=None):
        with self.lock: return self.data.get(k, default)
    def set(self, k, v):
        with self.lock: self.data[k] = v; self._flush()
    def update(self, **kw):
        with self.lock: self.data.update(kw); self._flush()
    def _flush(self):
        try: atomic_write(self.path, json.dumps(self.data).encode())
        except OSError: pass
