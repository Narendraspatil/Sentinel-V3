"""Credential protection: Windows DPAPI (machine scope) + restrictive ACLs.

Machine scope is needed because setup runs as an admin user but the service runs as SYSTEM.
Any local process that can read secret.bin could decrypt it, so the file is also ACL-locked to
SYSTEM + Administrators. A local administrator can still obtain it: that is an inherent limit."""
import base64, os, subprocess
from . import settings

try:
    import win32crypt  # type: ignore
except Exception:
    win32crypt = None

_ENTROPY = b"sentinel-v3-device-secret"
_LOCAL_MACHINE = 0x4

def _insecure_ok(): return os.environ.get("SENTINEL_ALLOW_INSECURE_STORE") == "1"

def protect(data: bytes) -> bytes:
    if win32crypt: return win32crypt.CryptProtectData(data, "sentinel", _ENTROPY, None, None, _LOCAL_MACHINE)
    if _insecure_ok(): return b"PLAIN:" + base64.b64encode(data)
    raise RuntimeError("DPAPI unavailable (pywin32 missing)")

def unprotect(blob: bytes) -> bytes:
    if blob.startswith(b"PLAIN:") and _insecure_ok(): return base64.b64decode(blob[6:])
    if win32crypt: return win32crypt.CryptUnprotectData(blob, _ENTROPY, None, None, _LOCAL_MACHINE)[1]
    raise RuntimeError("DPAPI unavailable (pywin32 missing)")

def store_secret(secret: str):
    settings.atomic_write(settings.SECRET_PATH, protect(secret.encode()))
    lock_down(settings.SECRET_PATH)

def load_secret() -> str:
    try:
        with open(settings.SECRET_PATH, "rb") as f: blob = f.read()
        return unprotect(blob).decode()
    except FileNotFoundError: raise settings.ConfigError("secret.bin is missing")
    except Exception as e: raise settings.ConfigError(f"secret.bin unreadable/corrupt: {type(e).__name__}")

def lock_down(path: str):
    if os.name != "nt": return
    grant = "(OI)(CI)F" if os.path.isdir(path) else "F"
    subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", f"*S-1-5-18:{grant}", f"*S-1-5-32-544:{grant}"],
                   capture_output=True, creationflags=0x08000000, check=False)
