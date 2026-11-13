"""HTTPS client for the Edge Functions. Never talks to the database directly."""
import requests

class AuthInvalid(Exception): pass
class AuthRevoked(Exception): pass
class NetworkError(Exception): pass
class ApiError(Exception):
    def __init__(self, status, code): super().__init__(f"{status}:{code}"); self.status, self.code = status, code

class DeviceAPI:
    def __init__(self, base_url, device_id, secret, timeout=20):
        self.base, self.device_id, self.secret, self.timeout = base_url.rstrip("/"), device_id, secret, timeout
        self.s = requests.Session()

    def _post(self, fn, payload, timeout=None):
        try:
            r = self.s.post(f"{self.base}/{fn}", json=payload, timeout=timeout or self.timeout,
                            headers={"x-device-id": self.device_id, "x-device-secret": self.secret})
        except requests.RequestException as e:
            raise NetworkError(type(e).__name__)
        try: body = r.json()
        except ValueError: body = {}
        if r.status_code == 401: raise AuthInvalid(body.get("error", "invalid"))
        if r.status_code == 403 and body.get("error") == "revoked": raise AuthRevoked()
        if r.status_code >= 500 or r.status_code == 429: raise NetworkError(f"http_{r.status_code}")
        if r.status_code >= 400: raise ApiError(r.status_code, body.get("error", "error"))
        return body

    def sync(self, payload, timeout=None): return self._post("device-sync", payload, timeout)
    def events(self, events, timeout=None): return self._post("device-events", {"events": events}, timeout)
    def command_result(self, command_id, status, result=None):
        return self._post("device-command-result", {"command_id": command_id, "status": status, "result": result or {}})
    def rotate(self): return self._post("device-rotate", {})["device_secret"]

def register(base_url, payload, timeout=30):
    r = requests.post(f"{base_url.rstrip('/')}/device-register", json=payload, timeout=timeout)
    try: body = r.json()
    except ValueError: body = {}
    if r.status_code != 200: raise ApiError(r.status_code, body.get("error", "error"))
    return body
