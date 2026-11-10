// Called daily by GitHub Actions. Performs real, harmless DB reads/writes (activity for Supabase),
// records the result, writes an integrity checkpoint over the event log, flags silent devices and
// (only if configured) prunes OLD HEARTBEATS. Security events are never deleted.
import { handler, json, sb, safeEqual, HttpError, rateLimit, clientIp, readBody, sha256Hex, serverEvents } from "../_shared/util.ts";

handler(async (req) => {
  rateLimit(`hc:${clientIp(req)}`, 20, 60_000);
  const expected = Deno.env.get("HEALTHCHECK_SECRET") ?? "";
  if (expected.length < 24 || !safeEqual(req.headers.get("x-healthcheck-secret") ?? "", expected)) throw new HttpError(401, "unauthorized");
  const b = await readBody(req, 2_000);
  const source = typeof b.source === "string" ? b.source.slice(0, 40) : "unknown";
  const started = Date.now(); const details: Record<string, unknown> = {};
  try {
    const { count: devices } = await sb.from("devices").select("id", { count: "exact", head: true });
    details.devices = devices;

    // checkpoint: hash chain over events received since the previous checkpoint
    const { data: prev } = await sb.from("log_checkpoints").select("up_to,digest").order("created_at", { ascending: false }).limit(1).maybeSingle();
    const since = prev?.up_to ?? "1970-01-01T00:00:00Z"; const upTo = new Date().toISOString();
    const { data: evs } = await sb.from("security_events").select("id,device_id,deduplication_id,event_timestamp,severity,message")
      .gt("received_at", since).lte("received_at", upTo).order("received_at").order("id").limit(50_000);
    if (evs && evs.length) {
      const digest = await sha256Hex((prev?.digest ?? "") + "|" + evs.map((e) => `${e.id}:${e.deduplication_id}:${e.event_timestamp}:${e.severity}:${e.message}`).join("\n"));
      await sb.from("log_checkpoints").insert({ up_to: upTo, event_count: evs.length, digest, prev_digest: prev?.digest ?? null });
      details.checkpoint_events = evs.length;
    }

    // devices silent for > 1 hour that were not stopped deliberately
    const cutoff = new Date(Date.now() - 3_600_000).toISOString();
    const { data: silent } = await sb.from("devices").select("id,device_name").eq("is_active", true).neq("status", "pending").lt("last_seen_at", cutoff);
    const bucket = new Date().toISOString().slice(0, 10);
    for (const d of silent ?? []) await serverEvents(d.id, [{ event_type: "device_silent", category: "system_health", severity: "medium",
      message: `No contact from ${d.device_name} for over 1 hour`, dedup: `silent-${bucket}` }]);
    details.silent_devices = silent?.length ?? 0;

    // optional operational retention (heartbeats only)
    const { data: ret } = await sb.from("app_settings").select("value").eq("key", "heartbeat_retention_days").maybeSingle();
    if (typeof ret?.value === "number") {
      await sb.from("device_heartbeats").delete().lt("timestamp", new Date(Date.now() - ret.value * 86_400_000).toISOString());
      details.heartbeat_retention_days = ret.value;
    }
    await sb.from("system_health_checks").insert({ source, success: true, response_status: 200, duration_ms: Date.now() - started, details });
    return json(req, { ok: true, checked_at: new Date().toISOString() });   // no DB information in the response
  } catch (e) {
    console.error("health-check failed", e instanceof Error ? e.message : "error");
    await sb.from("system_health_checks").insert({ source, success: false, response_status: 500, duration_ms: Date.now() - started, details: { error: "check_failed" } });
    throw e;
  }
});
