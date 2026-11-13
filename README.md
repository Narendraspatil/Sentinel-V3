# Sentinel 3.0

Windows laptop security monitoring and response: **GitHub Pages dashboard → Supabase (Auth, Postgres + RLS, Edge Functions) → Windows agent**. No webcam / photo features.

Full step-by-step setup: open **`docs/index.html`** in a browser.

## Layout
| Path | Purpose |
|---|---|
| `supabase/migrations/` | Schema, constraints, indexes, RLS, append-only triggers |
| `supabase/functions/` | 8 Edge Functions (`device-register`, `device-sync`, `device-events`, `device-command-result`, `device-rotate`, `admin-api`, `admin-bootstrap`, `health-check`) |
| `web/` | Static dashboard (GitHub Pages) |
| `agent/` | Windows service (Python) |
| `.github/workflows/` | `pages.yml` (deploy), `supabase-keepalive.yml` (daily) |
| `install.ps1` | One-line laptop installer (downloads the GitHub release, verifies SHA-256, registers, installs the service) |
| `.github/workflows/release-agent.yml` | Builds `SentinelAgent.exe` on tag `v*` and publishes it as a GitHub Release |
| `tools/make_manifest.py` | Trusted release hashes |
| `tests/`, `supabase/tests/` | pytest agent tests, SQL RLS/integrity tests |

## Environment variables
| Where | Name | Purpose |
|---|---|---|
| Supabase secrets | `DEVICE_SECRET_PEPPER` (≥32 chars) | keys the HMAC of device secrets/enrollment tokens |
| Supabase secrets | `HEALTHCHECK_SECRET` (≥24) | shared with the GitHub Action |
| Supabase secrets | `BOOTSTRAP_SECRET` (≥24) | first-admin creation; delete afterwards |
| Supabase secrets | `ALLOWED_ORIGIN` | exact dashboard origin(s) for CORS |
| GitHub secrets | `SUPABASE_FUNCTIONS_URL`, `HEALTHCHECK_SECRET` | keep-alive workflow |
| GitHub variables | `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY` | public dashboard config |

See `.env.example`. The Supabase secret/service-role key is never used outside Edge Functions.

## Dependencies
Agent: `requests`, `psutil`, `watchdog`, `pywin32`. Removed: `opencv-python` (and all camera code). Backend: no Railway, FastAPI, SQLAlchemy or bcrypt anymore.

## Files by status (relative to the old guides' structure)
* **Created:** everything in this repository (fresh build).
* **Deleted / not carried over:** `camera.py`, `photos.py`, photo models and gallery, OpenCV, Railway files (`Procfile`, `railway.toml`), FastAPI `server/`, server-side template dashboard.
* **Modified:** none — the original source code was not available, so nothing was edited in place.

## Tests run
See `docs/TESTING_REPORT.md`.

## Security limitations
Sentinel detects and reports tampering; it cannot stop a local administrator. Details in the guide (section "Security limitations").
