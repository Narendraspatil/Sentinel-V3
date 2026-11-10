// Heartbeat + settings + command delivery in ONE request (keeps traffic and DB writes low).
import { handler, json, readBody, sb, authDevice, str, serverEvents, sha256Hex } from "../_shared/util.ts";

const HB_LOG_EVERY_MS = 5 * 60_000;

handler(async (req) => {
  const dev = await authDevice(req);
  const b = await readBody(req, 100_000);
  const now = new Date(); const nowIso = now.toISOString();
  const stopping = b.lifecycle === "stopping";
  const mode = b.current_mode === "secure" ? "secure" : "open";
  const sys = b.system_status && typeof b.system_status === "object" ? b.system_status : {};

  // ── trusted baselines: first report is adopted, later changes are alerts ──
  const baselines: Record<string, string> = { ...(dev.baselines ?? {}) };
  const evs: Parameters<typeof serverEvents>[1] = [];
  let mismatch = false;
  for (const [k, v] of [["config", b.config_fingerprint], ["service", b.service_fingerprint]] as const) {
    if (typeof v !== "string" || v.length > 128) continue;
    if (!baselines[k]) baselines[k] = v;
    else if (baselines[k] !== v) {
      mismatch = true;
      evs.push({ event_type: `${k}_fingerprint_changed`, category: "integrity", severity: "high",
        message: `Agent ${k} fingerprint differs from the trusted baseline`,
        details: { expected: baselines[k], observed: v }, dedup: `baseline-${k}-${v.slice(0, 16)}`,
        extra: { check_type: `${k}_fingerprint`, expected: baselines[k], observed: v } });
    }
  }
  // ── compare reported file hashes with the published release manifest ──────
  let releaseVerified = false;
  const ver = str(b.agent_version, 32);
  if (ver && b.file_hashes && typeof b.file_hashes === "object") {
    const { data: rel } = await sb.from("agent_releases").select("file_hashes").eq("version", ver).maybeSingle();
    if (rel) {
      const bad: string[] = [];
      for (const [f, h] of Object.entries(rel.file_hashes as Record<string, string>))
        if ((b.file_hashes as Record<string, string>)[f] !== h) bad.push(f);
      if (bad.length) {
        mismatch = true;
        evs.push({ event_type: "agent_file_hash_mismatch", category: "integrity", severity: "critical",
          message: `Agent files differ from release ${ver}: ${bad.slice(0, 5).join(", ")}`,
          details: { files: bad, version: ver }, dedup: `release-${ver}-${(await sha256Hex(bad.sort().join("|"))).slice(0, 16)}`,
          extra: { check_type: "file_hash", expected: "release manifest", observed: bad.join(", ").slice(0, 500) } });
      } else releaseVerified = true;
    }
  }
  const integrity = mismatch ? "mismatch" : releaseVerified ? "verified" : "unknown";

  const upd: Record<string, unknown> = {
    last_heartbeat: nowIso, last_seen_at: nowIso, current_mode: mode, system_status: sys,
    status: stopping ? "agent_stopped" : "online", integrity_status: integrity, baselines,
    agent_version: ver, hostname: str(b.hostname, 128) ?? dev.hostname, os_version: str(b.os_version, 128) ?? dev.os_version,
  };
  if (!dev.last_hb_logged_at || now.getTime() - new Date(dev.last_hb_logged_at).getTime() > HB_LOG_EVERY_MS) {
    upd.last_hb_logged_at = nowIso;
    await sb.from("device_heartbeats").insert({ device_id: dev.id, agent_version: ver, current_mode: mode,
      service_status: stopping ? "stopping" : "running", system_status: sys, metadata: { buffer: b.buffer ?? null } });
  }
  await sb.from("devices").update(upd).eq("id", dev.id);
  await serverEvents(dev.id, evs);

  // ── commands ──────────────────────────────────────────────────────────────
  await sb.from("device_commands").update({ status: "expired" })
    .eq("device_id", dev.id).in("status", ["pending", "delivered"]).lt("expires_at", nowIso);
  let commands: unknown[] = [];
  if (!stopping) {
    const redeliver = new Date(now.getTime() - 120_000).toISOString();
    const { data: cmds } = await sb.from("device_commands")
      .select("id,command_type,command_payload,created_at,expires_at").eq("device_id", dev.id)
      .or(`status.eq.pending,and(status.eq.delivered,delivered_at.lt.${redeliver})`)
      .gt("expires_at", nowIso).order("created_at").limit(10);
    commands = cmds ?? [];
    if (cmds?.length) await sb.from("device_commands").update({ status: "delivered", delivered_at: nowIso })
      .in("id", cmds.map((c) => c.id)).in("status", ["pending", "delivered"]);
  }

  const { data: settings } = await sb.from("device_settings").select("*").eq("device_id", dev.id).maybeSingle();
  const { data: latest } = await sb.from("agent_releases").select("version").eq("is_latest", true).maybeSingle();
  return json(req, {
    server_time: nowIso, compromised: !!dev.is_compromised, commands,
    settings: settings && settings.settings_version !== b.settings_version ? settings : null,
    settings_version: settings?.settings_version ?? null,
    heartbeat_interval: settings?.heartbeat_interval ?? 30, latest_agent_version: latest?.version ?? null,
  });
});
