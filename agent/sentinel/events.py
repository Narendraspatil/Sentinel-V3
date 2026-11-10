"""Event creation: severity model, category switches, dedup ids."""
import logging, threading, uuid
from datetime import datetime, timezone

log = logging.getLogger("sentinel.events")
SEVERITIES = ("low", "medium", "high", "critical")
ALWAYS_ON = {"agent", "system_health", "command", "service"}

def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

class Emitter:
    def __init__(self, buffer, policy, wake_upload: threading.Event):
        self.buffer, self.policy, self.wake = buffer, policy, wake_upload

    def emit(self, event_type, category, severity, message, details=None, dedup_id=None, ts=None):
        if severity not in SEVERITIES: severity = "low"
        if severity != "critical" and category not in ALWAYS_ON and not self.policy.category_enabled(category):
            return False
        ev = {"dedup_id": dedup_id or uuid.uuid4().hex, "event_type": event_type[:64], "category": category,
              "severity": severity, "source": "agent", "message": message[:1000], "details": details or {},
              "event_timestamp": ts or utcnow_iso()}
        try: added = self.buffer.add(ev)
        except Exception:
            log.exception("could not buffer event %s", event_type); return False
        log.info("event %s/%s %s", category, severity, event_type)
        if severity in ("high", "critical"): self.wake.set()
        return added
