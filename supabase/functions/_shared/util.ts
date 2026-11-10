// Shared helpers for all Sentinel Edge Functions (Deno).
import { createClient } from "npm:@supabase/supabase-js@2";

const URL_ = Deno.env.get("SUPABASE_URL")!;
// Custom secrets cannot start with SUPABASE_, so SB_SECRET_KEY lets you use the new secret key;
// otherwise fall back to the auto-injected service role key.
const KEY_ = Deno.env.get("SB_SECRET_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
export const sb = createClient(URL_, KEY_, { auth: { persistSession: false, autoRefreshToken: false } });

export class HttpError extends Error {
  constructor(public status: number, public code: string, public extra?: Record<string, unknown>) { super(code); }
}

const ALLOWED = (Deno.env.get("ALLOWED_ORIGIN") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
export function cors(req: Request) {
  const o = req.headers.get("origin") ?? "";
  return {
    "Access-Control-Allow-Origin": ALLOWED.includes(o) ? o : "null",
    "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-device-id, x-device-secret",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
export const json = (req: Request, data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...cors(req), "Content-Type": "application/json", "Cache-Control": "no-store" } });

export function handler(fn: (req: Request) => Promise<Response>) {
  Deno.serve(async (req) => {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
    if (req.method !== "POST") return json(req, { error: "method_not_allowed" }, 405);
    try { return await fn(req); }
    catch (e) {
      if (e instanceof HttpError) return json(req, { error: e.code, ...(e.extra ?? {}) }, e.status);
      console.error("unhandled", e instanceof Error ? e.message : "error"); // never echo internals/secrets
      return json(req, { error: "internal_error" }, 500);
    }
  });
}

export async function readBody(req: Request, max = 1_000_000): Promise<Record<string, any>> {
  const t = await req.text();
  if (t.length > max) throw new HttpError(413, "payload_too_large");
  try { const v = JSON.parse(t || "{}"); if (typeof v !== "object" || v === null || Array.isArray(v)) throw 0; return v; }
  catch { throw new HttpError(400, "invalid_json"); }
}

// ── crypto ──────────────────────────────────────────────────────────────────
const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export async function hmacHex(secret: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
export async function sha256Hex(msg: string) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(msg))); }
function pepper() {
  const p = Deno.env.get("DEVICE_SECRET_PEPPER");
  if (!p || p.length < 32) throw new Error("DEVICE_SECRET_PEPPER missing/too short");
  return p;
}
// Device secrets are 256-bit random values, so a keyed HMAC-SHA256 (server-side pepper) is a
// sound, fast verifier. A DB leak alone does not allow offline guessing without the pepper.
export const hashSecret = (s: string) => hmacHex(pepper(), s);
export function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
export function randomSecret(bytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── best-effort in-memory rate limiting (per function instance) ─────────────
const hits = new Map<string, number[]>();
export function rateLimit(key: string, max: number, windowMs: number) {
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.length || now - v[v.length - 1] > windowMs) hits.delete(k);
  if (arr.length > max) throw new HttpError(429, "rate_limited");
}
const fails = new Map<string, number[]>();
function failCount(ip: string) { const now = Date.now(); const a = (fails.get(ip) ?? []).filter((t) => now - t < 60_000); fails.set(ip, a); return a.length; }
function noteFail(ip: string) { const a = fails.get(ip) ?? []; a.push(Date.now()); fails.set(ip, a); }

export const clientIp = (req: Request) =>
  (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || (req.headers.get("cf-connecting-ip") ?? "unknown");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (s: unknown): s is string => typeof s === "string" && UUID.test(s);
export const str = (v: unknown, max: number): string | null =>
  typeof v === "string" ? v.slice(0, max) : null;

// ── device authentication ───────────────────────────────────────────────────
export async function authDevice(req: Request) {
  const ip = clientIp(req);
  if (failCount(ip) >= 10) throw new HttpError(429, "rate_limited");
  const id = req.headers.get("x-device-id") ?? "";
  const secret = req.headers.get("x-device-secret") ?? "";
  const reject = async (reason: string, devId: string | null) => {
    noteFail(ip);
    await sb.from("device_auth_failures").insert({ device_id: devId, ip_address: ip, reason });
    throw new HttpError(401, "invalid_credentials");
  };
  if (!isUuid(id) || secret.length < 20 || secret.length > 128) return reject("malformed", null);

  const [{ data: dev }, { data: cred }] = await Promise.all([
    sb.from("devices").select("*").eq("id", id).maybeSingle(),
    sb.from("device_credentials").select("secret_hash").eq("device_id", id).maybeSingle(),
  ]);
  if (!dev || !cred) return reject("unknown_device", null);
  if (!safeEqual(await hashSecret(secret), cred.secret_hash)) return reject("bad_secret", id);
  // Only a caller who proved knowledge of the secret learns that the device is revoked.
  if (!dev.is_active || dev.revoked_at) throw new HttpError(403, "revoked");
  return dev as Record<string, any>;
}

// ── admin authentication (server-side; never trust the browser) ─────────────
const RANK: Record<string, number> = { viewer: 0, admin: 1, owner: 2 };
export async function authAdmin(req: Request, minRole: "viewer" | "admin" | "owner" = "admin") {
  const jwt = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!jwt) throw new HttpError(401, "unauthenticated");
  const { data, error } = await sb.auth.getUser(jwt);
  if (error || !data.user) throw new HttpError(401, "unauthenticated");
  const { data: p } = await sb.from("admin_profiles").select("*").eq("id", data.user.id).maybeSingle();
  if (!p || !p.is_active) throw new HttpError(403, "not_an_admin");
  let aal = "aal1";
  try { aal = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).aal ?? "aal1"; } catch { /* keep aal1 */ }
  const { data: ok } = await sb.rpc("mfa_satisfied", { p_uid: p.id, p_aal: aal });
  if (!ok) throw new HttpError(403, "mfa_required");
  if (RANK[p.role] < RANK[minRole]) throw new HttpError(403, "insufficient_role");
  return { user: data.user, profile: p as Record<string, any> };
}

export async function audit(adminId: string | null, action: string, deviceId: string | null, details: unknown, req: Request) {
  await sb.from("admin_audit_logs").insert({ admin_id: adminId, action, target_device_id: deviceId, details: details ?? {}, ip_address: clientIp(req) });
}

export const CATEGORIES = ["security","login","usb","file","application","integrity","defender","firewall","service","network","system_health","agent","command","auth"];
export const SEVERITIES = ["low","medium","high","critical"];

// Insert server-generated events (idempotent via deduplication_id).
export async function serverEvents(deviceId: string, evs: Array<{ event_type: string; category: string; severity: string; message: string; details?: unknown; dedup: string; extra?: { check_type: string; expected?: string; observed?: string } }>) {
  if (!evs.length) return;
  const rows = evs.map((e) => ({
    device_id: deviceId, event_type: e.event_type, category: e.category, severity: e.severity, source: "server",
    message: e.message, details: e.details ?? {}, event_timestamp: new Date().toISOString(), deduplication_id: e.dedup,
  }));
  const { data } = await sb.from("security_events").upsert(rows, { onConflict: "device_id,deduplication_id", ignoreDuplicates: true }).select("id,deduplication_id,severity");
  const byDedup = new Map(evs.map((e) => [e.dedup, e]));
  const integ = (data ?? []).filter((r) => byDedup.get(r.deduplication_id)?.extra).map((r) => {
    const e = byDedup.get(r.deduplication_id)!;
    return { device_id: deviceId, event_id: r.id, check_type: e.extra!.check_type, severity: r.severity, expected: e.extra!.expected ?? null, observed: e.extra!.observed ?? null, details: e.details ?? {} };
  });
  if (integ.length) await sb.from("agent_integrity_events").insert(integ);
}
