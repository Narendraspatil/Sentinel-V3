// Batch event ingestion. Idempotent: duplicates (same device + deduplication_id) are ignored but
// still acknowledged, so the agent can safely delete them from its offline buffer.
import { handler, json, readBody, sb, authDevice, HttpError, CATEGORIES, SEVERITIES, rateLimit } from "../_shared/util.ts";

const MAX_BATCH = 200;

handler(async (req) => {
  const dev = await authDevice(req);
  rateLimit(`ev:${dev.id}`, 60, 60_000);
  const b = await readBody(req, 2_000_000);
  if (!Array.isArray(b.events) || b.events.length === 0 || b.events.length > MAX_BATCH) throw new HttpError(400, "invalid_batch");

  const rows: Record<string, unknown>[] = []; const accepted: string[] = []; const rejected: { dedup_id: string; reason: string }[] = [];
  const maxFuture = Date.now() + 10 * 60_000;
  for (const e of b.events) {
    const dedup = typeof e?.dedup_id === "string" ? e.dedup_id.slice(0, 128) : "";
    const bad = (reason: string) => rejected.push({ dedup_id: dedup, reason });
    if (!dedup) { bad("missing_dedup_id"); continue; }
    if (typeof e.event_type !== "string" || !e.event_type || e.event_type.length > 64) { bad("event_type"); continue; }
    if (!CATEGORIES.includes(e.category)) { bad("category"); continue; }
    if (!SEVERITIES.includes(e.severity)) { bad("severity"); continue; }
    if (typeof e.message !== "string") { bad("message"); continue; }
    const t = Date.parse(e.event_timestamp);
    if (!Number.isFinite(t)) { bad("event_timestamp"); continue; }
    const details = e.details && typeof e.details === "object" && !Array.isArray(e.details) ? e.details : {};
    if (JSON.stringify(details).length > 16_000) { bad("details_too_large"); continue; }
    rows.push({
      device_id: dev.id, event_type: e.event_type, category: e.category, severity: e.severity,
      source: typeof e.source === "string" ? e.source.slice(0, 64) : "agent", message: e.message.slice(0, 1000), details,
      event_timestamp: new Date(Math.min(t, maxFuture)).toISOString(),   // original time preserved (offline buffering)
      correlation_id: typeof e.correlation_id === "string" ? e.correlation_id.slice(0, 128) : null, deduplication_id: dedup,
    });
    accepted.push(dedup);
  }
  if (rows.length) {
    const { data: inserted, error } = await sb.from("security_events")
      .upsert(rows, { onConflict: "device_id,deduplication_id", ignoreDuplicates: true }).select("id,deduplication_id,category,severity,details,message");
    if (error) throw new Error("insert failed");   // agent keeps buffer and retries
    const integ = (inserted ?? []).filter((r) => r.category === "integrity").map((r) => ({
      device_id: dev.id, event_id: r.id, check_type: String((r.details as any)?.check ?? "agent_reported"), severity: r.severity,
      expected: (r.details as any)?.expected ? String((r.details as any).expected).slice(0, 500) : null,
      observed: (r.details as any)?.observed ? String((r.details as any).observed).slice(0, 500) : null, details: r.details,
    }));
    if (integ.length) await sb.from("agent_integrity_events").insert(integ);
  }
  await sb.from("devices").update({ last_seen_at: new Date().toISOString() }).eq("id", dev.id);
  return json(req, { accepted, rejected });
});
