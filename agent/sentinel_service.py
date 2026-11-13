"""Windows Service host (pywin32). Top-level module on purpose: pywin32 registers the class by module name and
PythonPath, so it must be importable without package-relative imports.

Design rules (these fix 'service stops by itself'):
  * report RUNNING immediately, so the Service Control Manager never times out a slow start;
  * the service process NEVER exits because the agent failed: a supervisor retries with back-off;
  * a stop / PC shutdown is answered within a few seconds (network work is time-boxed);
  * a watchdog restarts any worker thread that died."""
import logging, os, sys, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servicemanager, win32event, win32service, win32serviceutil  # type: ignore
from sentinel import settings
from sentinel.bootlog import boot_log

log = logging.getLogger("sentinel.service")
WATCHDOG_SECONDS = 30
STOP_BUDGET_SECONDS = 8

class SentinelService(win32serviceutil.ServiceFramework):
    _svc_name_ = settings.SERVICE_NAME
    _svc_display_name_ = settings.SERVICE_DISPLAY
    _svc_description_ = "Sentinel laptop security monitoring agent"

    def __init__(self, args):
        super().__init__(args)
        self.halt = win32event.CreateEvent(None, 0, 0, None); self.agent = None

    def SvcStop(self):
        boot_log("stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=15000)
        win32event.SetEvent(self.halt)

    def SvcShutdown(self):
        boot_log("system shutdown")
        self.SvcStop()

    def _wait(self, seconds):
        """True if a stop was requested while waiting."""
        return win32event.WaitForSingleObject(self.halt, int(seconds * 1000)) == win32event.WAIT_OBJECT_0

    def SvcDoRun(self):
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        boot_log("service running")
        try:
            from sentinel import logging_setup
            logging_setup.setup()
        except Exception:
            boot_log("logging setup failed", exc=True)
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        try:
            self._supervise()
        except Exception:
            boot_log("supervisor crashed", exc=True); log.exception("supervisor crashed")
            raise
        boot_log("service stopped cleanly")

    def _supervise(self):
        fails = 0
        while True:
            wait = None
            try:
                from sentinel.core import Agent
                self.agent = Agent(); self.agent.start(); fails = 0
                boot_log("agent started")
            except settings.ConfigError as e:
                # Missing/corrupt config or credentials: stay alive, look again in a minute (admin may be fixing it).
                log.error("cannot start: %s", e); boot_log(f"cannot start (config): {e}")
                servicemanager.LogErrorMsg(f"Sentinel cannot start: {e}"); wait = 60
            except Exception:
                fails += 1; wait = min(10 * 2 ** min(fails, 4), 120)
                log.exception("agent failed to start (attempt %d), retry in %ds", fails, wait); boot_log(f"agent failed to start (attempt {fails})", exc=True)
            if wait is not None:
                if self._wait(wait): return
                continue
            while True:                                    # healthy: watchdog loop
                if self._wait(WATCHDOG_SECONDS):
                    self._stop_agent(); return
                try: self.agent.ensure_threads()
                except Exception: log.exception("watchdog error")

    def _stop_agent(self):
        ag = self.agent
        if not ag: return
        t = threading.Thread(target=ag.shutdown, daemon=True); t.start()
        waited = 0
        while t.is_alive() and waited < STOP_BUDGET_SECONDS:          # keep telling Windows we are still stopping
            t.join(2); waited += 2
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=15000)
        if t.is_alive(): boot_log("shutdown exceeded budget; exiting anyway")

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SentinelService)
