import json, logging, os
from logging.handlers import RotatingFileHandler
from . import settings

class _Json(logging.Formatter):
    def format(self, r):
        d = {"t": self.formatTime(r, "%Y-%m-%dT%H:%M:%S"), "lvl": r.levelname, "logger": r.name, "msg": r.getMessage()}
        if r.exc_info: d["exc"] = self.formatException(r.exc_info)
        return json.dumps(d)

def setup(level=logging.INFO):
    os.makedirs(settings.LOG_DIR, exist_ok=True)
    root = logging.getLogger(); root.setLevel(level)
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        h = RotatingFileHandler(os.path.join(settings.LOG_DIR, "sentinel.log"), maxBytes=5_000_000, backupCount=5, encoding="utf-8")
        h.setFormatter(_Json()); root.addHandler(h)
