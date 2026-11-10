"""Windows Security event log monitor (needs SYSTEM/Administrator).
Validated IDs: 4624 logon, 4625 failed logon, 4634/4647 logoff, 4720 user created, 4726 user deleted,
4732/4733 local group member added/removed, 4740 lockout, 4672 special privileges (only logged for admins
via 4732), 4719 audit policy changed, 1102 audit log cleared. Sysmon (optional) from its Operational log."""
import logging, subprocess, time, xml.etree.ElementTree as ET
from collections import deque
from .common import CREATE_NO_WINDOW

log = logging.getLogger("sentinel.winlog")
NS = {"e": "http://schemas.microsoft.com/win/2004/08/event/"}
IDS = [4624, 4625, 4634, 4647, 4720, 4726, 4732, 4733, 4740, 4719, 1102]
LOGON_TYPES = {"2": "interactive", "7": "unlock", "10": "remote interactive (RDP)", "11": "cached interactive"}
SKIP_USERS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}

def _query(channel, ids, after_record, count=200):
    q = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + f") and EventRecordID>{after_record}]]"
    r = subprocess.run(["wevtutil", "qe", channel, f"/q:{q}", "/f:xml", f"/c:{count}", "/rd:false"],
                       capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW)
    if r.returncode != 0: raise RuntimeError(r.stderr.strip()[:200] or "wevtutil failed")
    root = ET.fromstring("<Events xmlns:e='http://schemas.microsoft.com/win/2004/08/event/'>" + r.stdout.replace('xmlns="http://schemas.microsoft.com/win/2004/08/event/"', "") + "</Events>") if r.stdout.strip() else None
    return [] if root is None else list(root)

def _parse(ev):
    sysn = ev.find("System"); eid = int(sysn.findtext("EventID")); rid = int(sysn.findtext("EventRecordID"))
    ts = sysn.find("TimeCreated").get("SystemTime")
    data = {d.get("Name"): (d.text or "") for d in ev.iterfind("EventData/Data")}
    return eid, rid, ts, data

class WinLogMonitor:
    name = "winlog"
    def __init__(self, ctx): self.ctx, self.fail_times = ctx, {}
    def interval(self): return self.ctx.cfg["winlog_interval"]

    def run_once(self):
        em, st = self.ctx.emitter, self.ctx.state
        self._channel("Security", IDS, "rec_security", em, st, self._handle_security)
        if self.ctx.cfg.get("sysmon_enabled"):
            self._channel("Microsoft-Windows-Sysmon/Operational", self.ctx.cfg["sysmon_event_ids"], "rec_sysmon", em, st, self._handle_sysmon)

    def _channel(self, channel, ids, key, em, st, handler):
        last = st.get(key)
        try:
            if last is None:   # first run: start from the newest record, never replay history
                import re
                r = subprocess.run(["wevtutil", "qe", channel, "/c:1", "/rd:true", "/f:xml"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
                m = re.search(r"<EventRecordID>(\d+)</EventRecordID>", r.stdout)
                st.set(key, int(m.group(1)) if m else 0); return
            maxrec = last
            for ev in _query(channel, ids, last):
                eid, rid, ts, d = _parse(ev); maxrec = max(maxrec, rid)
                handler(em, eid, rid, ts, d)
            if maxrec != last: st.set(key, maxrec)
        except Exception as e:
            log.warning("%s read failed: %s", channel, e)
            em.emit("eventlog_unreadable", "agent", "medium", f"Cannot read {channel}: {str(e)[:150]}", dedup_id=f"elog-{channel[:12]}-{int(time.time()//3600)}")

    def _handle_security(self, em, eid, rid, ts, d):
        user = d.get("TargetUserName") or d.get("SubjectUserName") or "?"
        dom = d.get("TargetDomainName", "")
        did = f"win-{eid}-{rid}"
        if eid == 4624:
            lt = d.get("LogonType", "")
            if lt not in LOGON_TYPES or user.upper() in SKIP_USERS or user.endswith("$") or user.upper().startswith(("DWM-", "UMFD-")): return
            sev = "medium" if lt == "10" else "low"
            em.emit("logon_success", "login", sev, f"Logon: {dom}\\{user} ({LOGON_TYPES[lt]})", {"user": user, "domain": dom, "logon_type": lt, "source_ip": d.get("IpAddress"), "record": rid}, did, ts)
        elif eid == 4625:
            em.emit("logon_failed", "login", "low", f"Failed logon for {dom}\\{user} (type {d.get('LogonType')})", {"user": user, "logon_type": d.get("LogonType"), "source_ip": d.get("IpAddress"), "status": d.get("Status"), "record": rid}, did, ts)
            dq = self.fail_times.setdefault(user, deque(maxlen=50)); now = time.time(); dq.append(now)
            n = sum(1 for t in dq if now - t < 300)
            if n >= self.ctx.cfg["failed_logon_threshold"]:
                em.emit("logon_failed_burst", "login", "medium", f"{n} failed logons for {user} within 5 minutes", {"user": user, "count": n}, f"burst-{user}-{int(now//300)}")
        elif eid in (4634, 4647):
            lt = d.get("LogonType", "2")
            if eid == 4634 and lt not in LOGON_TYPES: return
            if user.upper() in SKIP_USERS or user.endswith("$"): return
            em.emit("logoff", "login", "low", f"Logoff: {user}", {"user": user, "record": rid}, did, ts)
        elif eid == 4720: em.emit("user_created", "login", "high", f"User account created: {user} by {d.get('SubjectUserName')}", {"user": user, "by": d.get("SubjectUserName")}, did, ts)
        elif eid == 4726: em.emit("user_deleted", "login", "high", f"User account deleted: {user} by {d.get('SubjectUserName')}", {"user": user, "by": d.get("SubjectUserName")}, did, ts)
        elif eid in (4732, 4733):
            grp = d.get("TargetUserName", ""); admin = grp.lower() in ("administrators", "administratoren")
            em.emit("group_member_added" if eid == 4732 else "group_member_removed", "login", "critical" if (admin and eid == 4732) else "high",
                    f"{'Added to' if eid == 4732 else 'Removed from'} group {grp}: {d.get('MemberName') or d.get('MemberSid')}", {"group": grp, "member": d.get("MemberName") or d.get("MemberSid"), "by": d.get("SubjectUserName")}, did, ts)
        elif eid == 4740: em.emit("account_lockout", "login", "high", f"Account locked out: {user}", {"user": user, "caller": d.get("CallerComputerName")}, did, ts)
        elif eid == 4719: em.emit("audit_policy_changed", "security", "high", "System audit policy was changed", {"by": d.get("SubjectUserName")}, did, ts)
        elif eid == 1102: em.emit("audit_log_cleared", "security", "critical", f"Security audit log was cleared by {d.get('SubjectUserName', '?')}", {"by": d.get("SubjectUserName")}, did, ts)

    def _handle_sysmon(self, em, eid, rid, ts, d):
        if eid == 1:
            img = (d.get("Image") or "").lower(); cmd = d.get("CommandLine", "")
            if any(w in img for w in self.ctx.policy.watch_processes) or ("powershell" in img and ("-enc" in cmd.lower() or "downloadstring" in cmd.lower())):
                em.emit("sysmon_process_create", "application", "high", f"Sysmon: suspicious process {img.split(chr(92))[-1]}", {"image": d.get("Image"), "command_line": cmd[:400], "parent": d.get("ParentImage"), "user": d.get("User")}, f"sysmon-{rid}", ts)
