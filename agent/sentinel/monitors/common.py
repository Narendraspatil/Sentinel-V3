import json, logging, subprocess, os
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

def run_ps(script: str, timeout=30):
    """Run a PowerShell snippet, return stdout text ('' on failure)."""
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        return r.stdout.strip()
    except Exception as e:
        logging.getLogger("sentinel.ps").warning("powershell failed: %s", type(e).__name__)
        return ""

def run_ps_json(script: str, timeout=30):
    out = run_ps(script + " | ConvertTo-Json -Depth 4 -Compress", timeout)
    try: return json.loads(out) if out else None
    except ValueError: return None
