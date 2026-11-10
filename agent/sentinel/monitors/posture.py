"""Defender / firewall / remote-access posture. Reports state in the heartbeat and raises events on change.
Read-only: Sentinel never changes Windows security settings by itself."""
import logging
from .common import run_ps_json
log = logging.getLogger("sentinel.posture")
DEF = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureAge,AntispywareEnabled"
FW = "Get-NetFirewallProfile | Select-Object Name,Enabled"
CFA = "(Get-MpPreference).EnableControlledFolderAccess"
RDP = "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections"

class PostureMonitor:
    name = "posture"
    def __init__(self, ctx): self.ctx, self.status, self.prev = ctx, {}, {}
    def interval(self): return self.ctx.cfg["posture_interval"]
    def run_once(self):
        em = self.ctx.emitter; st = {}
        d = run_ps_json(DEF)
        if isinstance(d, dict):
            st["defender"] = {"antivirus": bool(d.get("AntivirusEnabled")), "realtime": bool(d.get("RealTimeProtectionEnabled")),
                              "tamper": bool(d.get("IsTamperProtected")), "sig_age_hours": (d.get("AntivirusSignatureAge") or 0) * 24}
        f = run_ps_json(FW)
        if f:
            f = f if isinstance(f, list) else [f]
            st["firewall"] = [{"name": p["Name"], "enabled": bool(p["Enabled"])} for p in f]
        cfa = run_ps_json(CFA)
        if cfa is not None: st["controlled_folder_access"] = bool(cfa) and cfa not in (0, "0")
        rdp = run_ps_json(RDP)
        if rdp is not None: st["rdp_enabled"] = rdp in (0, "0")
        self.status = st
        p = self.prev
        def chg(key, was, now, etype, cat, sev, msg):
            if was is not None and was != now: em.emit(etype, cat, sev, msg, {"previous": was, "current": now})
        dv, pd = st.get("defender", {}), p.get("defender", {})
        if dv:
            chg("rt", pd.get("realtime"), dv["realtime"], "defender_realtime_changed", "defender", "high" if not dv["realtime"] else "low", f"Defender real-time protection {'ENABLED' if dv['realtime'] else 'DISABLED'}")
            chg("av", pd.get("antivirus"), dv["antivirus"], "defender_av_changed", "defender", "high" if not dv["antivirus"] else "low", f"Defender antivirus {'enabled' if dv['antivirus'] else 'DISABLED'}")
            chg("tp", pd.get("tamper"), dv["tamper"], "defender_tamper_changed", "defender", "high" if not dv["tamper"] else "low", f"Defender Tamper Protection {'enabled' if dv['tamper'] else 'DISABLED'}")
            if dv["sig_age_hours"] > 7 * 24: em.emit("defender_signatures_old", "defender", "medium", f"Defender signatures are {int(dv['sig_age_hours']/24)} days old", dedup_id=f"sig-{int(__import__('time').time()//86400)}")
        pf = {x["name"]: x["enabled"] for x in p.get("firewall", [])}
        for x in st.get("firewall", []):
            chg("fw", pf.get(x["name"]), x["enabled"], "firewall_profile_changed", "firewall", "high" if not x["enabled"] else "low", f"Firewall profile {x['name']} {'enabled' if x['enabled'] else 'DISABLED'}")
        chg("cfa", p.get("controlled_folder_access"), st.get("controlled_folder_access"), "controlled_folder_access_changed", "defender", "medium", "Controlled Folder Access setting changed")
        chg("rdp", p.get("rdp_enabled"), st.get("rdp_enabled"), "rdp_setting_changed", "network", "high", f"Remote Desktop {'ENABLED' if st.get('rdp_enabled') else 'disabled'}")
        self.prev = st
