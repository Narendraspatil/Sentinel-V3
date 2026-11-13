"""Crash-recovery configuration for the Windows service (the service class itself is in sentinel_service.py).

Recovery: restart after 5s, 15s, then every 60s for as long as it keeps failing (Windows repeats the last
action). Every restart is visible in the dashboard as an `unclean_shutdown` / `service_crash_loop` event."""
import logging, os, subprocess, sys
from . import settings

log = logging.getLogger("sentinel.service")

def configure_recovery(name=settings.SERVICE_NAME):
    subprocess.run(["sc", "failure", name, "reset=", "3600", "actions=", "restart/5000/restart/15000/restart/60000/restart/60000"], capture_output=True, creationflags=0x08000000)
    subprocess.run(["sc", "failureflag", name, "1"], capture_output=True, creationflags=0x08000000)   # also on non-zero exit
    subprocess.run(["sc", "config", name, "start=", "delayed-auto"], capture_output=True, creationflags=0x08000000)
