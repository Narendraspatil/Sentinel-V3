// Enrols a new laptop using a ONE-TIME enrollment token created by an admin.
import { handler, json, readBody, sb, hashSecret, randomSecret, rateLimit, clientIp, str, serverEvents } from "../_shared/util.ts";
import { HttpError } from "../_shared/util.ts";

handler(async (req) => {
  rateLimit(`reg:${clientIp(req)}`, 10, 60_000);
  const b = await readBody(req, 20_000);
  const token = str(b.enrollment_token, 200);
  const name = str(b.device_name, 100)?.trim();
  if (!token || token.length < 20 || !name) throw new HttpError(400, "invalid_request");

  const tokenHash = await hashSecret(token);
  // Atomic single-use: only one caller can flip used_at from null.
  const { data: tok } = await sb.from("device_enrollment_tokens")
    .update({ used_at: new Date().toISOString() })
    .eq("token_hash", tokenHash).is("used_at", null).gt("expires_at", new Date().toISOString())
    .select("id").maybeSingle();
  if (!tok) throw new HttpError(401, "invalid_enrollment_token");

  const secret = randomSecret(32);
  const { data: dev, error } = await sb.from("devices").insert({
    device_name: name, hostname: str(b.hostname, 128), operating_system: "Windows",
    os_version: str(b.os_version, 128), agent_version: str(b.agent_version, 32), status: "pending",
    baselines: {},
  }).select("id").single();
  if (error || !dev) throw new Error("device insert failed");

  await sb.from("device_credentials").insert({ device_id: dev.id, secret_hash: await hashSecret(secret) });
  const { data: settings } = await sb.from("device_settings").insert({ device_id: dev.id }).select("*").single();
  await sb.from("device_enrollment_tokens").update({ used_by_device: dev.id }).eq("id", tok.id);
  await sb.from("device_registration_history").insert({ device_id: dev.id, action: "registered", details: { hostname: str(b.hostname, 128), ip: clientIp(req) } });
  await serverEvents(dev.id, [{ event_type: "device_registered", category: "system_health", severity: "low", message: `Device "${name}" registered`, dedup: "registered" }]);

  // The plaintext secret is returned exactly once and never stored.
  return json(req, { device_id: dev.id, device_secret: secret, settings });
});
