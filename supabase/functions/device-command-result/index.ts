// The ONLY way a command becomes acknowledged / executing / completed / failed.
// A device can only touch its own commands, and states may only move forward.
import { handler, json, readBody, sb, authDevice, HttpError, isUuid, serverEvents } from "../_shared/util.ts";

const ORDER: Record<string, number> = { pending: 0, delivered: 1, acknowledged: 2, executing: 3, completed: 4, failed: 4 };

handler(async (req) => {
  const dev = await authDevice(req);
  const b = await readBody(req, 50_000);
  if (!isUuid(b.command_id) || !(b.status in ORDER) || b.status === "pending" || b.status === "delivered") throw new HttpError(400, "invalid_request");

  const { data: cmd } = await sb.from("device_commands").select("*").eq("id", b.command_id).eq("device_id", dev.id).maybeSingle();
  if (!cmd) throw new HttpError(404, "command_not_found");               // other device's command looks identical to "missing"
  if (["completed", "failed", "expired", "cancelled"].includes(cmd.status)) throw new HttpError(409, "command_closed", { status: cmd.status });
  if (new Date(cmd.expires_at) < new Date()) {
    await sb.from("device_commands").update({ status: "expired" }).eq("id", cmd.id);
    throw new HttpError(409, "command_expired");
  }
  if (ORDER[b.status] < ORDER[cmd.status]) throw new HttpError(409, "invalid_transition");

  const now = new Date().toISOString();
  const upd: Record<string, unknown> = { status: b.status };
  if (b.status === "acknowledged") upd.acknowledged_at = now;
  if (b.status === "executing") { upd.executed_at = now; upd.acknowledged_at = cmd.acknowledged_at ?? now; }
  if (b.status === "completed" || b.status === "failed") {
    upd.completed_at = now; upd.executed_at = cmd.executed_at ?? now; upd.acknowledged_at = cmd.acknowledged_at ?? now;
    const r = b.result && typeof b.result === "object" ? b.result : {};
    upd.result = JSON.stringify(r).length < 16_000 ? r : { truncated: true };
  }
  const { error } = await sb.from("device_commands").update(upd).eq("id", cmd.id).eq("status", cmd.status);
  if (error) throw new Error("update failed");

  // Only an acknowledged completion changes server-side state.
  if (b.status === "completed" && (cmd.command_type === "secure_mode_on" || cmd.command_type === "secure_mode_off")) {
    const on = cmd.command_type === "secure_mode_on";
    await sb.from("device_settings").update({ secure_mode: on }).eq("device_id", dev.id);
    await sb.from("devices").update({ current_mode: on ? "secure" : "open" }).eq("id", dev.id);
  }
  if (b.status === "completed" || b.status === "failed") {
    await serverEvents(dev.id, [{ event_type: `command_${b.status}`, category: "command", severity: b.status === "failed" ? "medium" : "low",
      message: `Command ${cmd.command_type} ${b.status}`, details: { command_id: cmd.id, type: cmd.command_type, result: upd.result }, dedup: `cmd-${cmd.id}-${b.status}` }]);
  }
  return json(req, { ok: true, status: b.status });
});
