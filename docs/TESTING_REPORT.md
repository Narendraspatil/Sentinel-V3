# Sentinel 3.0 – Testing report

Run in a Linux sandbox (no Windows, no Deno, no real Supabase). Anything not listed below was **not** executed.

## Executed and passing
| Area | How | Result |
|---|---|---|
| Database schema | Applied `migrations/*.sql` to PostgreSQL 16 with a stub of Supabase's `auth` schema and roles | applies cleanly |
| RLS / privileges | `supabase/tests/rls_test.sql`: anon blocked; non-admin sees no rows; admin read-only (cannot insert/update/delete, change roles, read `device_credentials` or `token_hash`); MFA: aal1 denied / aal2 allowed once a TOTP factor exists; RLS enabled+forced on every table | all passed |
| Log integrity | same file: security events cannot be edited/deleted (only resolution fields), audit log and checkpoints fully append-only; duplicate dedup id rejected; invalid category (`photo`) and command type rejected; settings version bump | all passed |
| Edge Functions | `tsc --strict` type-check of all 9 TypeScript files (Deno APIs shimmed) | no errors |
| Agent (24 pytest tests) | buffer dedup/ack/original timestamps/severity ordering/never drop high+critical/corruption recovery/restart persistence; policy offline persistence; category switches vs critical; config missing/corrupt/http rejected; fingerprints; credential corruption; Windows event handling (failed-logon burst, RDP, service-logon noise filtered, admin group add = critical); integrity (config tamper, credential loss, file change); **mock HTTP server**: acknowledged upload empties buffer, outage keeps rows then resends without loss/duplicates, 1,500-event batches, 401 vs 403-revoked; command lifecycle ack→executing→completed, replay protection, expiry, unsupported/failed, isolation refused unless enabled, secure-off refused while compromised, final result survives network loss | 24 passed |
| Manifest tool | hashes equal the hashes the agent itself reports | match |
| Setup guide | HTML well-formed, all anchors resolve | ok |

## NOT executed (must be verified on your systems)
* **Edge Function runtime behavior** (no Deno here): register/sync/events/command flows end-to-end, CORS, rate limiting, bootstrap, keep-alive. Follow the guide's checklist after deploying.
* **Supabase Auth**: real login, TOTP enrolment, sign-up disabled, session refresh, brute-force limits.
* **GitHub Actions / Pages** workflows (syntax follows the standard actions but they have not run).
* **Windows-only code**: DPAPI, ACLs (`icacls`), `wevtutil` queries, Win32 service hosting (source and PyInstaller exe), service recovery, USB/Defender/firewall PowerShell, lock-workstation, network isolation, Sysmon. These were written against documented Windows behavior but never run on Windows.
* Dashboard UI in a real browser, including mobile layout.
