"""Durable offline event buffer (SQLite WAL): original timestamps, INSERT OR IGNORE dedup,
delete only after server ack, corrupt-DB quarantine, bounded (drops oldest LOW/MEDIUM only;
HIGH/CRITICAL are never dropped automatically), payload protected with DPAPI."""
import json, os, sqlite3, threading, time
from . import protect

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_SCHEMA = "CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, dedup_id TEXT UNIQUE NOT NULL, sev INTEGER NOT NULL, ts TEXT NOT NULL, payload BLOB NOT NULL)"

class EventBuffer:
    def __init__(self, path, max_rows=100_000):
        self.path, self.max_rows, self.lock = path, max_rows, threading.RLock()
        self.recovered, self.dropped, self.db = False, 0, None
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = self._open()

    def _open(self):
        try:
            db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
            db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=NORMAL")
            db.execute(_SCHEMA); db.execute("SELECT count(*) FROM events").fetchone(); db.commit()
            return db
        except sqlite3.DatabaseError:
            return self._recover()

    def _recover(self):
        try:
            if self.db: self.db.close()
        except Exception: pass
        if os.path.exists(self.path): os.replace(self.path, f"{self.path}.corrupt-{int(time.time())}")
        for ext in ("-wal", "-shm"):
            try: os.remove(self.path + ext)
            except OSError: pass
        self.recovered = True
        db = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        db.execute("PRAGMA journal_mode=WAL"); db.execute(_SCHEMA); db.commit()
        return db

    def _run(self, fn):
        with self.lock:
            try: return fn(self.db)
            except sqlite3.DatabaseError:
                self.db = self._recover(); return fn(self.db)

    def add(self, ev: dict) -> bool:
        blob = protect.protect(json.dumps(ev).encode())
        def f(db):
            cur = db.execute("INSERT OR IGNORE INTO events(dedup_id,sev,ts,payload) VALUES(?,?,?,?)",
                             (ev["dedup_id"], SEV_RANK[ev["severity"]], ev["event_timestamp"], blob))
            db.commit()
            n = db.execute("SELECT count(*) FROM events").fetchone()[0]
            if n > self.max_rows:
                k = max(n - self.max_rows, self.max_rows // 100)
                c2 = db.execute("DELETE FROM events WHERE id IN (SELECT id FROM events WHERE sev<=1 ORDER BY id LIMIT ?)", (k,))
                self.dropped += c2.rowcount; db.commit()
            return cur.rowcount == 1
        return self._run(f)

    def batch(self, n=100):
        rows = self._run(lambda db: db.execute("SELECT dedup_id,payload FROM events ORDER BY sev DESC, id LIMIT ?", (n,)).fetchall())
        out = []
        for dedup, blob in rows:
            try: out.append(json.loads(protect.unprotect(bytes(blob))))
            except Exception: self.discard([dedup])
        return out

    def ack(self, dedup_ids): self.discard(dedup_ids)

    def discard(self, dedup_ids):
        if not dedup_ids: return
        def f(db):
            db.executemany("DELETE FROM events WHERE dedup_id=?", [(d,) for d in dedup_ids]); db.commit()
        self._run(f)

    def stats(self):
        rows, oldest = self._run(lambda db: db.execute("SELECT count(*), min(ts) FROM events").fetchone())
        return {"rows": rows, "pct": round(100 * rows / self.max_rows, 1), "oldest": oldest}

    def take_dropped(self):
        d, self.dropped = self.dropped, 0
        return d
