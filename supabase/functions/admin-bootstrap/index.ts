// One-time creation of the first (owner) administrator. Works only while NO admin exists and
// only with the BOOTSTRAP_SECRET you set in Supabase secrets. Delete that secret afterwards.
import { handler, json, readBody, sb, safeEqual, HttpError, rateLimit, clientIp } from "../_shared/util.ts";

handler(async (req) => {
  rateLimit(`boot:${clientIp(req)}`, 5, 10 * 60_000);
  const expected = Deno.env.get("BOOTSTRAP_SECRET") ?? "";
  const given = req.headers.get("x-bootstrap-secret") ?? "";
  if (expected.length < 24 || !safeEqual(given, expected)) throw new HttpError(401, "unauthorized");

  const { count } = await sb.from("admin_profiles").select("id", { count: "exact", head: true });
  if ((count ?? 0) > 0) throw new HttpError(409, "already_bootstrapped");

  const b = await readBody(req, 5_000);
  const email = typeof b.email === "string" ? b.email.trim().toLowerCase() : "";
  const pw = typeof b.password === "string" ? b.password : "";
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || pw.length < 12) throw new HttpError(400, "invalid_email_or_password_too_short");

  const { data, error } = await sb.auth.admin.createUser({ email, password: pw, email_confirm: true });
  if (error || !data.user) throw new HttpError(400, "create_user_failed");
  const { error: pe } = await sb.from("admin_profiles").insert({ id: data.user.id, email, role: "owner" });
  if (pe) { await sb.auth.admin.deleteUser(data.user.id); throw new Error("profile insert failed"); }
  await sb.from("admin_audit_logs").insert({ admin_id: data.user.id, action: "admin_bootstrapped", details: {}, ip_address: clientIp(req) });
  return json(req, { ok: true, message: "Owner created. Log in, enrol TOTP MFA, then delete BOOTSTRAP_SECRET." });
});
