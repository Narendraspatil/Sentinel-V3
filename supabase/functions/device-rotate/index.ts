// Credential rotation. Allowed only while an acknowledged, unexpired rotate_credentials command exists.
import { handler, json, sb, authDevice, HttpError, hashSecret, randomSecret } from "../_shared/util.ts";

handler(async (req) => {
  const dev = await authDevice(req);
  const { data: cmd } = await sb.from("device_commands").select("id")
    .eq("device_id", dev.id).eq("command_type", "rotate_credentials")
    .in("status", ["acknowledged", "executing"]).gt("expires_at", new Date().toISOString()).limit(1).maybeSingle();
  if (!cmd) throw new HttpError(403, "no_rotation_command");
  const secret = randomSecret(32);
  await sb.from("device_credentials").update({ secret_hash: await hashSecret(secret), rotated_at: new Date().toISOString() }).eq("device_id", dev.id);
  await sb.from("device_registration_history").insert({ device_id: dev.id, action: "rotated", details: { command_id: cmd.id } });
  return json(req, { device_secret: secret });
});
