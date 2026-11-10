// Every dashboard mutation goes through here: server-side admin check, validation, audit log.
import { handler, json, readBody, sb, authAdmin, audit, HttpError, isUuid, hashSecret, randomSecret, rateLimit, clientIp, serverEvents } from "../_shared/util.ts";

const COMMANDS = ["secure_mode_on","secure_mode_off","lock_workstation","security_scan","health_report","integrity_check",
  "refresh_config","restrict_apps","rotate_credentials","network_isolate","network_restore"];
const SENSITIVE = ["lock_workstation", "restrict_apps", "rotate_credentials", "network_isolate"];
const CAT_KEYS = ["login","usb","file","application","defender","firewall","service","network","integrity"];
const EXE = /^[\w .\-()+]{1,100}\.exe$/i;

const need = (c: unknown, code = "invalid_request") => { if (!c) throw new HttpError(400, code); };
const list = (v: unknown, test: (s: string) => boolean, max = 200): string[] => {
  need(Array.isArray(v) && v.length <= max);
  return (v as unknown[]).map((x) => { need(typeof x === "string" && test(x.trim())); return (x as string).trim(); });
};

handler(async (req) => {
  rateLimit(`adm:${clientIp(req)}`, 120, 60_000);
  const b = await readBody(req, 200_000);
  const action = String(b.action ?? "");
  const writeActions = action !== "record_login";
  const { profile } = await authAdmin(req, writeActions ? "admin" : "viewer");
  const me = profile.id as string;

  const loadDevice = async () => {
    need(isUuid(b.device_id));
    const { data } = await sb.from("devices").select("*").eq("id", b.device_id).maybeSingle();
    if (!data) throw new HttpError(404, "device_not_found");
    return data;
  };

  switch (action) {
    case "record_login": {
      await sb.from("admin_profiles").update({ last_login_at: new Date().toISOString() }).eq("id", me);
      await audit(me, "admin_login", null, {}, req);
      return json(req, { ok: true, role: profile.role });
    }

    case "create_enrollment_token": {
      const minutes = Math.min(Math.max(Number(b.ttl_minutes ?? 60), 5), 1440);
      const token = randomSecret(24);
      const { data } = await sb.from("device_enrollment_tokens").insert({
        token_hash: await hashSecret(token), label: String(b.label ?? "").slice(0, 100) || null, created_by: me,
        expires_at: new Date(Date.now() + minutes * 60_000).toISOString(),
      }).select("id,expires_at").single();
      await audit(me, "enrollment_token_created", null, { id: data!.id, minutes }, req);
      return json(req, { token, expires_at: data!.expires_at });   // shown once
    }

    case "create_command": {
      const d = await loadDevice();
      need(COMMANDS.includes(b.command_type));
      if (!d.is_active || d.revoked_at) throw new HttpError(409, "device_revoked");
      if (SENSITIVE.includes(b.command_type) && b.confirm !== true) throw new HttpError(400, "confirmation_required");
      let payload: Record<string, unknown> = {};
      if (b.command_type === "restrict_apps") {
        payload = { apps: list(b.payload?.apps, (s) => EXE.test(s), 50), minutes: Math.min(Math.max(Number(b.payload?.minutes ?? 60), 1), 1440) };
        need((payload.apps as string[]).length > 0);
      }
      if (b.command_type === "network_isolate") payload = { auto_restore_minutes: Math.min(Math.max(Number(b.payload?.auto_restore_minutes ?? 30), 5), 240) };
      const ttl = Math.min(Math.max(Number(b.ttl_minutes ?? 15), 1), 1440);
      const { data, error } = await sb.from("device_commands").insert({
        device_id: d.id, command_type: b.command_type, command_payload: payload, issued_by: me,
        expires_at: new Date(Date.now() + ttl * 60_000).toISOString(),
      }).select("id,expires_at").single();
      if (error) throw new Error("insert failed");
      await audit(me, "command_issued", d.id, { command_id: data.id, type: b.command_type, payload }, req);
      return json(req, { command_id: data.id, expires_at: data.expires_at, status: "pending" });
    }

    case "cancel_command": {
      need(isUuid(b.command_id));
      const { data } = await sb.from("device_commands").update({ status: "cancelled" }).eq("id", b.command_id).in("status", ["pending", "delivered"]).select("id,device_id").maybeSingle();
      if (!data) throw new HttpError(409, "not_cancellable");
      await audit(me, "command_cancelled", data.device_id, { command_id: data.id }, req);
      return json(req, { ok: true });
    }

    case "revoke_device": {
      const d = await loadDevice();
      if (b.confirm_name !== d.device_name) throw new HttpError(400, "confirmation_required");
      const now = new Date().toISOString();
      await sb.from("devices").update({ is_active: false, revoked_at: now, revoked_reason: String(b.reason ?? "").slice(0, 300) || null, status: "revoked" }).eq("id", d.id);
      await sb.from("device_commands").update({ status: "cancelled" }).eq("device_id", d.id).in("status", ["pending", "delivered"]);
      await sb.from("device_registration_history").insert({ device_id: d.id, action: "revoked", details: { by: me } });
      await audit(me, "device_revoked", d.id, { reason: b.reason ?? null }, req);
      return json(req, { ok: true });
    }

    case "mark_compromised": case "clear_compromised": {
      const d = await loadDevice();
      const on = action === "mark_compromised";
      if (on && b.confirm !== true) throw new HttpError(400, "confirmation_required");
      await sb.from("devices").update({ is_compromised: on }).eq("id", d.id);
      await sb.from("device_registration_history").insert({ device_id: d.id, action: on ? "compromised" : "compromise_cleared", details: { by: me } });
      if (on) await sb.from("device_commands").insert({ device_id: d.id, command_type: "secure_mode_on", issued_by: me, expires_at: new Date(Date.now() + 86_400_000).toISOString() });
      await serverEvents(d.id, [{ event_type: on ? "marked_compromised" : "compromise_cleared", category: "security", severity: on ? "critical" : "low",
        message: on ? "Device marked as compromised by an administrator" : "Compromised flag cleared", dedup: `compromised-${Date.now()}` }]);
      await audit(me, action, d.id, {}, req);
      return json(req, { ok: true });
    }

    case "update_settings": {
      const d = await loadDevice();
      const s = b.settings ?? {};
      const upd: Record<string, unknown> = { updated_by: me };
      if ("blocked_applications" in s) upd.blocked_applications = list(s.blocked_applications, (x) => EXE.test(x));
      if ("watch_processes" in s) upd.watch_processes = list(s.watch_processes, (x) => EXE.test(x));
      if ("protected_folders" in s) upd.protected_folders = list(s.protected_folders, (x) => x.length > 2 && x.length <= 260 && !/[\x00-\x1f<>"|?*]/.test(x));
      if ("monitoring_enabled" in s) { need(typeof s.monitoring_enabled === "boolean"); upd.monitoring_enabled = s.monitoring_enabled; }
      if ("heartbeat_interval" in s) { need(Number.isInteger(s.heartbeat_interval) && s.heartbeat_interval >= 15 && s.heartbeat_interval <= 600); upd.heartbeat_interval = s.heartbeat_interval; }
      if ("event_categories" in s) {
        const ec: Record<string, boolean> = {};
        for (const k of CAT_KEYS) { need(typeof s.event_categories?.[k] === "boolean"); ec[k] = s.event_categories[k]; }
        upd.event_categories = ec;
      }
      // secure_mode is deliberately NOT editable here: use the secure_mode_on/off commands so it is acknowledged.
      const { error } = await sb.from("device_settings").update(upd).eq("device_id", d.id);
      if (error) throw new Error("update failed");
      await audit(me, "settings_changed", d.id, { fields: Object.keys(upd).filter((k) => k !== "updated_by") }, req);
      return json(req, { ok: true });
    }

    case "resolve_event": {
      need(Array.isArray(b.event_ids) && b.event_ids.length > 0 && b.event_ids.length <= 200 && b.event_ids.every(isUuid));
      const { data } = await sb.from("security_events").update({ resolved: true, resolved_at: new Date().toISOString(), resolved_by: me, resolution_note: String(b.note ?? "").slice(0, 500) || null })
        .in("id", b.event_ids).select("id");
      await audit(me, "events_resolved", null, { count: data?.length ?? 0 }, req);
      return json(req, { resolved: data?.length ?? 0 });
    }

    case "accept_baseline": {      // admin deliberately re-trusts the device's current fingerprints
      const d = await loadDevice();
      await sb.from("devices").update({ baselines: {}, integrity_status: "unknown" }).eq("id", d.id);
      await audit(me, "baseline_reset", d.id, {}, req);
      return json(req, { ok: true });
    }

    case "publish_release": {
      const { profile: owner } = await authAdmin(req, "owner");
      need(typeof b.version === "string" && /^\d+\.\d+\.\d+([\-+][\w.]+)?$/.test(b.version));
      need(b.file_hashes && typeof b.file_hashes === "object" && Object.keys(b.file_hashes).length > 0 && Object.keys(b.file_hashes).length <= 200);
      for (const [k, v] of Object.entries(b.file_hashes)) need(k.length <= 200 && typeof v === "string" && /^[0-9a-f]{64}$/i.test(v as string));
      if (b.is_latest) await sb.from("agent_releases").update({ is_latest: false }).eq("is_latest", true);
      const { error } = await sb.from("agent_releases").upsert({ version: b.version, file_hashes: b.file_hashes, is_latest: !!b.is_latest, notes: String(b.notes ?? "").slice(0, 500) || null, created_by: owner.id });
      if (error) throw new Error("upsert failed");
      await audit(me, "release_published", null, { version: b.version, files: Object.keys(b.file_hashes).length }, req);
      return json(req, { ok: true });
    }

    case "set_retention": {
      await authAdmin(req, "owner");
      const days = b.heartbeat_retention_days;
      need(days === null || (Number.isInteger(days) && days >= 7 && days <= 3650));
      await sb.from("app_settings").upsert({ key: "heartbeat_retention_days", value: days, updated_at: new Date().toISOString() });
      await audit(me, "retention_changed", null, { heartbeat_retention_days: days }, req);
      return json(req, { ok: true });
    }

    default:
      throw new HttpError(400, "unknown_action");
  }
});
