import json, os, threading, time, uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
from sentinel import api as apimod, protect, settings
from sentinel.buffer import EventBuffer
from sentinel.events import Emitter, utcnow_iso
from sentinel.policy import Policy

def ev(sev="low", n=None):
    return {"dedup_id": n or uuid.uuid4().hex, "event_type": "t", "category": "file", "severity": sev, "source": "agent", "message": "m", "details": {}, "event_timestamp": utcnow_iso()}

# ── buffer ──────────────────────────────────────────────────────────────────
def test_buffer_dedup_and_ack(datadir):
    b = EventBuffer(str(datadir / "b.db"))
    assert b.add(ev(n="a")) is True and b.add(ev(n="a")) is False        # duplicate rejected locally
    assert len(b.batch()) == 1
    b.ack(["a"]); assert b.batch() == []

def test_buffer_keeps_original_timestamp_and_orders_by_severity(datadir):
    b = EventBuffer(str(datadir / "b.db")); old = ev("low", "old"); old["event_timestamp"] = "2020-01-01T00:00:00.000Z"
    b.add(old); b.add(ev("critical", "crit"))
    out = b.batch(); assert out[0]["dedup_id"] == "crit"
    assert [e for e in out if e["dedup_id"] == "old"][0]["event_timestamp"] == "2020-01-01T00:00:00.000Z"

def test_buffer_never_drops_high_or_critical_when_full(datadir):
    b = EventBuffer(str(datadir / "b.db"), max_rows=100)
    for i in range(10): b.add(ev("critical", f"c{i}"))
    for i in range(300): b.add(ev("low", f"l{i}"))
    ids = {e["dedup_id"] for e in b.batch(1000)}
    assert all(f"c{i}" in ids for i in range(10)) and b.take_dropped() > 0

def test_buffer_corruption_recovery(datadir):
    p = datadir / "b.db"; b = EventBuffer(str(p)); b.add(ev(n="x")); b.db.close()
    p.write_bytes(b"this is not a sqlite database" * 200)
    b2 = EventBuffer(str(p)); assert b2.recovered and b2.stats()["rows"] == 0
    assert b2.add(ev(n="y")) and any(f.startswith("b.db.corrupt-") for f in os.listdir(datadir))

def test_buffer_survives_restart(datadir):
    b = EventBuffer(str(datadir / "b.db")); b.add(ev(n="persist")); b.db.close()
    assert [e["dedup_id"] for e in EventBuffer(str(datadir / "b.db")).batch()] == ["persist"]

# ── policy / emitter ────────────────────────────────────────────────────────
def test_blocked_only_in_secure_mode_and_restriction(datadir):
    p = Policy(str(datadir / "p.json")); p.apply({"blocked_applications": ["Chrome.exe"]})
    assert p.blocked() == set(); p.set_secure(True); assert p.blocked() == {"chrome.exe"}
    p.set_secure(False); p.add_restriction(["x.exe"], 1); assert p.blocked() == {"x.exe"}

def test_policy_persists_for_offline_start(datadir):
    p = Policy(str(datadir / "p.json")); p.apply({"blocked_applications": ["a.exe"], "secure_mode": True, "settings_version": 7})
    q = Policy(str(datadir / "p.json")); assert q.secure_mode and q.version == 7 and q.blocked() == {"a.exe"}

def test_category_switch_but_critical_always_sent(datadir):
    b = EventBuffer(str(datadir / "b.db")); p = Policy(str(datadir / "p.json")); p.apply({"event_categories": {"usb": False}})
    e = Emitter(b, p, threading.Event())
    assert e.emit("u", "usb", "medium", "x") is False
    assert e.emit("u", "usb", "critical", "x") is True
    assert e.emit("u", "login", "low", "x") is True

# ── config / credentials / tamper ───────────────────────────────────────────
def test_config_missing_corrupt_and_http_rejected(datadir, monkeypatch):
    with pytest.raises(settings.ConfigError): settings.load_config()
    (datadir / "config.json").write_text("{not json")
    with pytest.raises(settings.ConfigError): settings.load_config()
    (datadir / "config.json").write_text(json.dumps({"server_url": "http://x", "device_id": "d"}))
    monkeypatch.delenv("SENTINEL_ALLOW_HTTP")
    with pytest.raises(settings.ConfigError, match="https"): settings.load_config()

def test_fingerprint_changes_on_url_or_device_change():
    a = {"server_url": "https://a", "device_id": "1", "service_name": "S"}
    assert settings.config_fingerprint(a) == settings.config_fingerprint(dict(a))
    assert settings.config_fingerprint(a) != settings.config_fingerprint({**a, "server_url": "https://evil"})
    assert settings.config_fingerprint(a) != settings.config_fingerprint({**a, "device_id": "2"})

def test_secret_roundtrip_and_corruption(datadir):
    protect.store_secret("s3cret-value"); assert protect.load_secret() == "s3cret-value"
    assert b"s3cret" not in (datadir / "secret.bin").read_bytes() or os.environ.get("SENTINEL_ALLOW_INSECURE_STORE") == "1"
    (datadir / "secret.bin").write_bytes(b"\x00garbage")
    with pytest.raises(settings.ConfigError): protect.load_secret()
    os.remove(datadir / "secret.bin")
    with pytest.raises(settings.ConfigError): protect.load_secret()

# ── Windows event parsing ───────────────────────────────────────────────────
def test_winlog_handlers(datadir):
    from sentinel.monitors.winlog import WinLogMonitor
    from types import SimpleNamespace
    b = EventBuffer(str(datadir / "b.db")); p = Policy(str(datadir / "p.json")); em = Emitter(b, p, threading.Event())
    m = WinLogMonitor(SimpleNamespace(cfg={**settings.DEFAULTS}, emitter=em, state=None, policy=p))
    for i in range(5): m._handle_security(em, 4625, i, "2026-01-01T00:00:00Z", {"TargetUserName": "bob", "TargetDomainName": "PC", "LogonType": "2"})
    m._handle_security(em, 4624, 10, "2026-01-01T00:00:00Z", {"TargetUserName": "bob", "TargetDomainName": "PC", "LogonType": "10", "IpAddress": "1.2.3.4"})
    m._handle_security(em, 4624, 11, "2026-01-01T00:00:00Z", {"TargetUserName": "SYSTEM", "LogonType": "5"})      # service noise ignored
    m._handle_security(em, 4732, 12, "2026-01-01T00:00:00Z", {"TargetUserName": "Administrators", "MemberName": "eve", "SubjectUserName": "x"})
    m._handle_security(em, 4720, 13, "2026-01-01T00:00:00Z", {"TargetUserName": "eve", "SubjectUserName": "x"})
    types = {e["dedup_id"]: e for e in b.batch(100)}
    kinds = [e["event_type"] for e in types.values()]
    assert kinds.count("logon_failed") == 5 and "logon_failed_burst" in kinds and "logon_success" in kinds
    assert next(e for e in types.values() if e["event_type"] == "group_member_added")["severity"] == "critical"
    assert next(e for e in types.values() if e["event_type"] == "logon_success")["severity"] == "medium"   # RDP
    assert sum(1 for e in types.values() if e["event_type"] == "logon_success") == 1
    m._handle_security(em, 4625, 0, "2026-01-01T00:00:00Z", {"TargetUserName": "bob", "LogonType": "2"})    # same record id -> same dedup
    assert b.stats()["rows"] == len(types)

# ── mock server for upload + commands ───────────────────────────────────────
class Mock(BaseHTTPRequestHandler):
    store = {"seen": set(), "fail": False, "results": [], "cmds": [], "revoked": False}
    def log_message(self, *a): pass
    def _send(self, code, obj):
        d = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(d))); self.end_headers(); self.wfile.write(d)
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}"); S = Mock.store
        if self.headers.get("x-device-secret") != "good-secret-good-secret-123": return self._send(401, {"error": "invalid_credentials"})
        if S["revoked"]: return self._send(403, {"error": "revoked"})
        if S["fail"]: return self._send(503, {"error": "down"})
        if self.path.endswith("/device-events"):
            acc = []; 
            for e in body["events"]: S["seen"].add(e["dedup_id"]); acc.append(e["dedup_id"])
            return self._send(200, {"accepted": acc, "rejected": []})
        if self.path.endswith("/device-command-result"): S["results"].append(body); return self._send(200, {"ok": True})
        if self.path.endswith("/device-sync"): c = S["cmds"]; S["cmds"] = []; return self._send(200, {"commands": c, "settings": None, "heartbeat_interval": 30, "compromised": False})
        self._send(404, {})

@pytest.fixture
def server():
    Mock.store.update(seen=set(), fail=False, results=[], cmds=[], revoked=False)
    s = HTTPServer(("127.0.0.1", 0), Mock); threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"; s.shutdown()

@pytest.fixture
def agent(datadir, server):
    settings.save_config({**settings.DEFAULTS, "server_url": server, "device_id": str(uuid.uuid4()), "device_name": "t", "batch_size": 10})
    protect.store_secret("good-secret-good-secret-123")
    from sentinel.core import Agent
    return Agent()

def test_upload_acknowledged_and_buffer_emptied(agent):
    for i in range(25): agent.emitter.emit("t", "login", "low", "m", dedup_id=f"e{i}")
    assert agent._upload_once() == 25 and agent.buffer.stats()["rows"] == 0 and len(Mock.store["seen"]) == 25

def test_offline_then_reconnect_no_loss_no_duplicates(agent):
    Mock.store["fail"] = True
    for i in range(12): agent.emitter.emit("t", "login", "high", "m", dedup_id=f"o{i}")
    with pytest.raises(apimod.NetworkError): agent._upload_once()
    assert agent.buffer.stats()["rows"] == 12                       # nothing deleted without an ack
    Mock.store["fail"] = False; agent._upload_once()
    assert agent.buffer.stats()["rows"] == 0 and len(Mock.store["seen"]) == 12

def test_bad_secret_and_revoked_are_distinguished(agent):
    agent.api.secret = "x" * 30
    with pytest.raises(apimod.AuthInvalid): agent.api.sync({})
    agent.api.secret = "good-secret-good-secret-123"; Mock.store["revoked"] = True
    with pytest.raises(apimod.AuthRevoked): agent.api.sync({})

def cmd(t, p=None, minutes=10):
    return {"id": str(uuid.uuid4()), "command_type": t, "command_payload": p or {}, "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()}

def statuses(): return [r["status"] for r in Mock.store["results"]]

def test_command_lifecycle_and_replay_protection(agent):
    c = cmd("secure_mode_on"); agent.runner.handle(c)
    assert statuses() == ["acknowledged", "executing", "completed"] and agent.policy.secure_mode
    agent.runner.handle(c); assert len(Mock.store["results"]) == 3     # duplicate delivery ignored

def test_expired_command_not_executed(agent):
    agent.runner.handle(cmd("secure_mode_on", minutes=-1)); assert Mock.store["results"] == [] and not agent.policy.secure_mode

def test_unsupported_and_failing_commands_report_failure(agent):
    agent.runner.handle(cmd("does_not_exist")); assert statuses()[-1] == "failed"
    Mock.store["results"].clear(); agent.runner.handle(cmd("restrict_apps", {"apps": ["notexe"]})); assert statuses()[-1] == "failed"
    Mock.store["results"].clear(); agent.runner.handle(cmd("network_isolate")); r = Mock.store["results"][-1]
    assert r["status"] == "failed" and "allow_network_isolation" in r["result"]["error"]

def test_secure_mode_off_refused_while_compromised(agent):
    agent.compromised = True; agent.runner.handle(cmd("secure_mode_off")); assert statuses()[-1] == "failed"

def test_final_result_survives_network_loss(agent):
    c = cmd("health_report"); Mock.store["fail"] = True
    agent.runner.handle(c); assert agent.state.get("pending_results")
    Mock.store["fail"] = False; agent.runner.flush_pending()
    assert any(r["status"] == "completed" for r in Mock.store["results"]) and not agent.state.get("pending_results")

def test_agent_refuses_to_start_with_corrupt_credentials(datadir, server):
    settings.save_config({**settings.DEFAULTS, "server_url": server, "device_id": "d"}); (datadir / "secret.bin").write_bytes(b"\x01junk")
    from sentinel.core import Agent
    with pytest.raises(settings.ConfigError): Agent()

def test_integrity_detects_config_change_and_credential_loss(agent):
    from sentinel.monitors.integrity import IntegrityMonitor
    m = IntegrityMonitor(agent); m.run_once()
    cfg = settings.load_config(); cfg["server_url"] = "http://evil.example"; settings.save_config(cfg); os.remove(settings.SECRET_PATH)
    m.run_once(); kinds = {e["event_type"] for e in agent.buffer.batch(100)}
    assert {"config_tampered", "credentials_unreadable"} <= kinds

def test_integrity_detects_file_modification_while_running(agent, monkeypatch):
    from sentinel.monitors import integrity
    monkeypatch.setattr(integrity, "file_hashes", lambda: {"a.py": "1"}); m = integrity.IntegrityMonitor(agent); m.run_once()
    monkeypatch.setattr(integrity, "file_hashes", lambda: {"a.py": "2"}); m.run_once()
    assert "agent_files_changed" in {e["event_type"] for e in agent.buffer.batch(100)}

def test_large_batch_upload(agent):
    agent.cfg["batch_size"] = 100
    for i in range(1500): agent.emitter.emit("t", "login", "low", "m", dedup_id=f"b{i}")
    assert agent._upload_once() == 1500 and len(Mock.store["seen"]) == 1500
