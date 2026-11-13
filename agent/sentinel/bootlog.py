"""Plain-file diagnostic log that works even when nothing else (logging, config, imports) does.
Written to %ProgramData%\\Sentinel\\logs\\service-boot.log; first place to look when the service will not stay running."""
import os, sys, time, traceback

def _path():
    d = os.environ.get("SENTINEL_DATA_DIR") or os.path.join(os.environ.get("ProgramData", r"C:\\ProgramData"), "Sentinel")
    return os.path.join(d, "logs", "service-boot.log")

def boot_log(msg, exc=False):
    try:
        p = _path(); os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p) and os.path.getsize(p) > 512_000: os.replace(p, p + ".old")
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} pid={os.getpid()} {msg}\n")
            if exc: f.write(traceback.format_exc() + "\n")
    except Exception:
        pass
