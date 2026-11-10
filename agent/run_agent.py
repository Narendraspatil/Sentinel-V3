"""Entry point for both `python run_agent.py <cmd>` and the PyInstaller SentinelAgent.exe.
With no arguments under the Service Control Manager it hosts the service; otherwise it is the CLI."""
import sys

def main():
    if len(sys.argv) == 1:
        try:
            import servicemanager, win32serviceutil  # type: ignore
            from sentinel_service import SentinelService
            servicemanager.Initialize(); servicemanager.PrepareToHostSingle(SentinelService); servicemanager.StartServiceCtrlDispatcher()
            return
        except Exception:
            pass
    from sentinel.cli import main as cli_main
    cli_main()

if __name__ == "__main__": main()
