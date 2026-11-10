"""USB storage monitor (polling, default 20 s; cheap CIM query). Records name/serial/PNP id, never files."""
import logging
from .common import run_ps_json
log = logging.getLogger("sentinel.usb")
SCRIPT = "Get-CimInstance Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' -or $_.PNPDeviceID -like 'USBSTOR*' } | Select-Object Model,SerialNumber,PNPDeviceID,Size"

class UsbMonitor:
    name = "usb"
    def __init__(self, ctx): self.ctx, self.current = ctx, None
    def interval(self): return self.ctx.cfg["usb_poll_seconds"]
    def run_once(self):
        data = run_ps_json(SCRIPT)
        if data is None and self.current is None: data = []
        if data is None: return
        devs = data if isinstance(data, list) else [data]
        now = {d["PNPDeviceID"]: d for d in devs if d.get("PNPDeviceID")}
        known = set(self.ctx.state.get("usb_known", []))
        if self.current is None:      # first scan: baseline without alerting for already-plugged devices
            self.current = set(now); known |= set(now); self.ctx.state.set("usb_known", sorted(known)); return
        for pid, d in now.items():
            if pid not in self.current:
                was_known = pid in known
                self.ctx.emitter.emit("usb_connected", "usb", "low" if was_known else "medium",
                    f"USB storage connected: {d.get('Model')}{'' if was_known else ' (new device)'}",
                    {"model": d.get("Model"), "serial": (d.get("SerialNumber") or "").strip(), "pnp_id": pid, "size_bytes": d.get("Size"), "previously_known": was_known})
                known.add(pid)
        for pid in self.current - set(now):
            self.ctx.emitter.emit("usb_disconnected", "usb", "low", "USB storage disconnected", {"pnp_id": pid})
        self.current = set(now); self.ctx.state.set("usb_known", sorted(known))
