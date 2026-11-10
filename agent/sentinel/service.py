"""Crash-recovery configuration for the Windows service (the service class itself is in sentinel_service.py).

Recovery: restart after 60s, 2 min, 5 min, then NO more restarts (reset counter after 1 day), so a failing
agent cannot loop forever; every restart is visible in the dashboard as an `unclean_shutdown` /
`service_crash_loop` event."""
import logging, os, subprocess, sys
from . import settings

log = logging.getLogger("sentinel.service")

def configure_recovery(name=settings.SERVICE_NAME):
    subprocess.run(["sc", "failure", name, "reset=", "86400", "actions=", "restart/60000/restart/120000/restart/300000"], capture_output=True, creationflags=0x08000000)
    subprocess.run(["sc", "failureflag", name, "1"], capture_output=True, creationflags=0x08000000)   # also on non-zero exit
    subprocess.run(["sc", "config", name, "start=", "delayed-auto"], capture_output=True, creationflags=0x08000000)
