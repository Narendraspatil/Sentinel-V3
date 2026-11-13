"""Entry point for both `python run_agent.py <cmd>` and the PyInstaller SentinelAgent.exe.
Started by the Service Control Manager with no arguments -> hosts the service. Started by a person -> CLI.
A real failure while hosting the service is LOGGED (service-boot.log) and re-raised; it is never silently
turned into the CLI (which used to make the service stop a moment after starting)."""
import sys

def main():
    if len(sys.argv) == 1:
        try:
            from sentinel.bootlog import boot_log
        except Exception:
            boot_log = lambda *a, **k: None
        try:
            import servicemanager  # type: ignore
            from sentinel_service import SentinelService
        except Exception:
            boot_log("service host import failed", exc=True); raise
        try:
            boot_log("service host starting")
            servicemanager.Initialize(); servicemanager.PrepareToHostSingle(SentinelService); servicemanager.StartServiceCtrlDispatcher()
            boot_log("service host exited normally"); return
        except Exception as e:
            if getattr(e, "winerror", None) == 1063:       # not started by the SCM (a person double-clicked it): show the CLI help
                boot_log("started interactively (not by the service manager)")
            else:
                boot_log("service host failed", exc=True); raise
    from sentinel.cli import main as cli_main
    cli_main()

if __name__ == "__main__": main()
