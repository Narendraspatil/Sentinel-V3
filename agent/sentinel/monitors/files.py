"""Protected-folder monitor (watchdog). Logs path/type/time only — never file contents.
Process attribution is not reliably available from ReadDirectoryChangesW, so it is not claimed."""
import logging, os, time, threading
from .. import settings
log = logging.getLogger("sentinel.files")
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None; FileSystemEventHandler = object

class _H(FileSystemEventHandler):
    def __init__(self, ctx): self.ctx, self.recent = ctx, {}
    def _go(self, kind, path, dest=None):
        if settings.is_self_write() and os.path.abspath(path).startswith(os.path.abspath(settings.DATA_DIR)): return
        now = time.time(); key = (kind, path)
        if now - self.recent.get(key, 0) < 2: return        # collapse bursts
        self.recent[key] = now
        if len(self.recent) > 2000: self.recent = {k: v for k, v in self.recent.items() if now - v < 5}
        sev = "high" if self.ctx.policy.secure_mode else "medium"
        d = {"path": path, "operation": kind}
        if dest: d["dest_path"] = dest
        self.ctx.emitter.emit(f"file_{kind}", "file", sev, f"Protected folder: {kind} {path}", d)
    def on_created(self, e): self._go("created", e.src_path)
    def on_modified(self, e):
        if not e.is_directory: self._go("modified", e.src_path)
    def on_deleted(self, e): self._go("deleted", e.src_path)
    def on_moved(self, e): self._go("renamed", e.src_path, e.dest_path)

class FileMonitor:
    name = "files"
    def __init__(self, ctx): self.ctx, self.obs, self.rev, self.alive_flag = ctx, None, -1, True
    def interval(self): return 10
    def run_once(self):
        if Observer is None: return
        p = self.ctx.policy
        if self.obs and self.obs.is_alive() and self.rev == p.folders_rev and p.monitoring_enabled: return
        self._stop()
        if not p.monitoring_enabled: return
        self.rev = p.folders_rev; self.obs = Observer(); h = _H(self.ctx)
        n = 0
        for f in p.protected_folders:
            if os.path.isdir(f):
                try: self.obs.schedule(h, f, recursive=True); n += 1
                except Exception as e: log.warning("cannot watch %s: %s", f, e)
            else: self.ctx.emitter.emit("protected_folder_missing", "file", "medium", f"Protected folder not found: {f}", {"path": f}, f"pfm-{abs(hash(f))}-{int(time.time()//86400)}")
        if n: self.obs.daemon = True; self.obs.start()
    def healthy(self): return self.obs is None or self.obs.is_alive() or not self.ctx.policy.protected_folders
    def _stop(self):
        if self.obs:
            try: self.obs.stop(); self.obs.join(2)
            except Exception: pass
            self.obs = None
