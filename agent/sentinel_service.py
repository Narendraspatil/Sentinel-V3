"""Windows Service host (pywin32). Top-level module on purpose: pywin32 registers the class by module name and
PythonPath, so it must be importable without package-relative imports."""
import logging, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servicemanager, win32event, win32service, win32serviceutil  # type: ignore
from sentinel import settings

log = logging.getLogger("sentinel.service")

class SentinelService(win32serviceutil.ServiceFramework):
    _svc_name_ = settings.SERVICE_NAME
    _svc_display_name_ = settings.SERVICE_DISPLAY
    _svc_description_ = "Sentinel laptop security monitoring agent"

    def __init__(self, args):
        super().__init__(args)
        self.halt = win32event.CreateEvent(None, 0, 0, None); self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.halt)

    def SvcShutdown(self): self.SvcStop()

    def SvcDoRun(self):
        from sentinel import logging_setup
        logging_setup.setup()
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, ""))
        try:
            from sentinel.core import Agent
            self.agent = Agent(); self.agent.start()
        except settings.ConfigError as e:
            # Missing/corrupt config or credentials: do NOT crash-loop. Log and wait for an administrator.
            log.error("cannot start: %s", e)
            servicemanager.LogErrorMsg(f"Sentinel cannot start: {e}")
            win32event.WaitForSingleObject(self.halt, win32event.INFINITE); return
        except Exception:
            log.exception("fatal start error"); raise
        win32event.WaitForSingleObject(self.halt, win32event.INFINITE)
        if self.agent: self.agent.shutdown()

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SentinelService)
