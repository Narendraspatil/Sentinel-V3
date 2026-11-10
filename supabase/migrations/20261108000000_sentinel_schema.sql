-- ============================================================================
-- Sentinel 3.0 — core schema, constraints, indexes, RLS
-- All timestamps are timestamptz (stored in UTC). IDs are UUIDs.
-- Device-facing writes happen ONLY through Edge Functions (service role).
-- The browser (authenticated admins) gets read-only access via RLS; every
-- mutation goes through the admin-api Edge Function so it is audited.
-- ============================================================================
create extension if not exists pgcrypto;

create or replace function public.touch_updated_at() returns trigger
language plpgsql as $$ begin new.updated_at = now(); return new; end $$;

-- ── 1. admin_profiles ───────────────────────────────────────────────────────
create table public.admin_profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  email         text not null,
  role          text not null default 'admin' check (role in ('owner','admin','viewer')),
  is_active     boolean not null default true,
  created_at    timestamptz not null default now(),
  last_login_at timestamptz
);

-- ── 2. devices (no secret here; see device_credentials) ─────────────────────
create table public.devices (
  id               uuid primary key default gen_random_uuid(),
  device_name      text not null check (char_length(device_name) between 1 and 100),
  operating_system text,
  os_version       text,
  agent_version    text,
  hostname         text,
  registered_at    timestamptz not null default now(),
  last_heartbeat   timestamptz,
  last_seen_at     timestamptz,
  last_hb_logged_at timestamptz,
  current_mode     text not null default 'open' check (current_mode in ('open','secure')),
  status           text not null default 'pending'
                   check (status in ('pending','online','offline','agent_stopped','revoked')),
  is_active        boolean not null default true,
  is_compromised   boolean not null default false,
  revoked_at       timestamptz,
  revoked_reason   text,
  system_status    jsonb not null default '{}'::jsonb,
  integrity_status text not null default 'unknown'
                   check (integrity_status in ('unknown','verified','mismatch','error')),
  baselines        jsonb not null default '{}'::jsonb,   -- trusted server-side fingerprints
  metadata         jsonb not null default '{}'::jsonb
);
create index devices_last_seen_idx on public.devices (last_seen_at desc);
create index devices_status_idx on public.devices (status, is_active);

-- Secret hashes live in their own table: no grants, no policies => unreachable from the browser.
create table public.device_credentials (
  device_id     uuid primary key references public.devices(id) on delete cascade,
  secret_hash   text not null,
  rotated_at    timestamptz not null default now()
);

-- ── 5. device_settings ──────────────────────────────────────────────────────
create table public.device_settings (
  id                 uuid primary key default gen_random_uuid(),
  device_id          uuid not null unique references public.devices(id) on delete cascade,
  blocked_applications text[] not null default '{}',
  protected_folders  text[] not null default '{}',
  watch_processes    text[] not null default '{mimikatz.exe,procdump.exe,psexec.exe,nc.exe,ncat.exe}',
  monitoring_enabled boolean not null default true,
  secure_mode        boolean not null default false,
  heartbeat_interval integer not null default 30 check (heartbeat_interval between 15 and 600),
  event_categories   jsonb not null default
    '{"login":true,"usb":true,"file":true,"application":true,"defender":true,"firewall":true,"service":true,"network":true,"integrity":true}',
  settings_version   bigint not null default 1,
  updated_at         timestamptz not null default now(),
  updated_by         uuid references public.admin_profiles(id)
);
create or replace function public.bump_settings_version() returns trigger language plpgsql as $$
begin new.settings_version = old.settings_version + 1; new.updated_at = now(); return new; end $$;
create trigger device_settings_bump before update on public.device_settings
  for each row execute function public.bump_settings_version();

-- ── 3. security_events (append-only; one table, separated by category) ──────
create table public.security_events (
  id               uuid primary key default gen_random_uuid(),
  device_id        uuid not null references public.devices(id) on delete cascade,
  event_type       text not null check (char_length(event_type) between 1 and 64),
  category         text not null check (category in
    ('security','login','usb','file','application','integrity','defender','firewall',
     'service','network','system_health','agent','command','auth')),
  severity         text not null check (severity in ('low','medium','high','critical')),
  source           text not null default 'agent',
  message          text not null check (char_length(message) <= 1000),
  details          jsonb not null default '{}'::jsonb,
  event_timestamp  timestamptz not null,
  received_at      timestamptz not null default now(),
  correlation_id   text,
  deduplication_id text not null,
  resolved         boolean not null default false,
  resolved_at      timestamptz,
  resolved_by      uuid references public.admin_profiles(id),
  resolution_note  text,
  unique (device_id, deduplication_id)
);
create index sec_dev_time_idx  on public.security_events (device_id, event_timestamp desc);
create index sec_time_idx      on public.security_events (event_timestamp desc);
create index sec_sev_idx       on public.security_events (severity, event_timestamp desc) where resolved = false;
create index sec_cat_idx       on public.security_events (device_id, category, event_timestamp desc);
create index sec_type_idx      on public.security_events (event_type);

-- Append-only: only the resolution columns may change; deletes are rejected.
-- (A database owner can still disable this trigger: it is a privileged trust boundary.)
create or replace function public.protect_append_only() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'security log rows cannot be deleted (append-only)';
  end if;
  if tg_table_name = 'security_events' then
    if (to_jsonb(new) - 'resolved' - 'resolved_at' - 'resolved_by' - 'resolution_note')
       is distinct from
       (to_jsonb(old) - 'resolved' - 'resolved_at' - 'resolved_by' - 'resolution_note') then
      raise exception 'security_events are append-only; only resolution fields may change';
    end if;
    return new;
  end if;
  raise exception '% is append-only', tg_table_name;
end $$;
create trigger sec_events_append_only before update or delete on public.security_events
  for each row execute function public.protect_append_only();

-- ── 9. agent_integrity_events ───────────────────────────────────────────────
create table public.agent_integrity_events (
  id          uuid primary key default gen_random_uuid(),
  device_id   uuid not null references public.devices(id) on delete cascade,
  event_id    uuid references public.security_events(id),
  check_type  text not null,
  severity    text not null check (severity in ('low','medium','high','critical')),
  expected    text,
  observed    text,
  details     jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);
create index integ_dev_idx on public.agent_integrity_events (device_id, created_at desc);
create trigger integ_append_only before update or delete on public.agent_integrity_events
  for each row execute function public.protect_append_only();

-- ── 4. device_heartbeats (sampled, not every beat) ──────────────────────────
create table public.device_heartbeats (
  id             uuid primary key default gen_random_uuid(),
  device_id      uuid not null references public.devices(id) on delete cascade,
  "timestamp"    timestamptz not null default now(),
  agent_version  text,
  current_mode   text,
  service_status text,
  system_status  jsonb not null default '{}'::jsonb,
  metadata       jsonb not null default '{}'::jsonb
);
create index hb_dev_time_idx on public.device_heartbeats (device_id, "timestamp" desc);

-- ── 6. device_commands ──────────────────────────────────────────────────────
create table public.device_commands (
  id              uuid primary key default gen_random_uuid(),
  device_id       uuid not null references public.devices(id) on delete cascade,
  command_type    text not null check (command_type in
    ('secure_mode_on','secure_mode_off','lock_workstation','security_scan','health_report',
     'integrity_check','refresh_config','restrict_apps','rotate_credentials',
     'network_isolate','network_restore')),
  command_payload jsonb not null default '{}'::jsonb,
  issued_by       uuid references public.admin_profiles(id),
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null,
  delivered_at    timestamptz,
  acknowledged_at timestamptz,
  executed_at     timestamptz,
  completed_at    timestamptz,
  status          text not null default 'pending' check (status in
    ('pending','delivered','acknowledged','executing','completed','failed','expired','cancelled')),
  result          jsonb
);
create index cmd_dev_idx    on public.device_commands (device_id, created_at desc);
create index cmd_pending_idx on public.device_commands (device_id, status) where status in ('pending','delivered');

-- ── enrollment tokens (one-time) & registration history ─────────────────────
create table public.device_enrollment_tokens (
  id             uuid primary key default gen_random_uuid(),
  token_hash     text not null unique,
  label          text,
  created_by     uuid references public.admin_profiles(id),
  created_at     timestamptz not null default now(),
  expires_at     timestamptz not null,
  used_at        timestamptz,
  used_by_device uuid references public.devices(id)
);
create table public.device_registration_history (
  id         uuid primary key default gen_random_uuid(),
  device_id  uuid references public.devices(id) on delete cascade,
  action     text not null check (action in ('registered','rotated','revoked','compromised','compromise_cleared')),
  details    jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create table public.device_auth_failures (
  id         bigint generated always as identity primary key,
  device_id  uuid,
  ip_address text,
  reason     text not null,
  created_at timestamptz not null default now()
);
create index authfail_idx on public.device_auth_failures (created_at desc);

-- ── trusted release manifest (server-side integrity baseline) ───────────────
create table public.agent_releases (
  version     text primary key,
  file_hashes jsonb not null default '{}'::jsonb,
  is_latest   boolean not null default false,
  notes       text,
  created_by  uuid references public.admin_profiles(id),
  created_at  timestamptz not null default now()
);
create unique index one_latest_release on public.agent_releases (is_latest) where is_latest;

create table public.app_settings (
  key        text primary key,
  value      jsonb,
  updated_at timestamptz not null default now()
);
insert into public.app_settings (key, value) values
  ('heartbeat_retention_days', 'null'),        -- null = keep forever
  ('offline_threshold_seconds', '120'),
  ('failed_logon_burst_threshold', '5');

-- ── 7. admin_audit_logs (append-only) ───────────────────────────────────────
create table public.admin_audit_logs (
  id               uuid primary key default gen_random_uuid(),
  admin_id         uuid references public.admin_profiles(id),
  action           text not null,
  target_device_id uuid references public.devices(id) on delete set null,
  details          jsonb not null default '{}'::jsonb,
  ip_address       text,
  created_at       timestamptz not null default now()
);
create index audit_time_idx on public.admin_audit_logs (created_at desc);
create index audit_dev_idx  on public.admin_audit_logs (target_device_id, created_at desc);
create trigger audit_append_only before update or delete on public.admin_audit_logs
  for each row execute function public.protect_append_only();

-- ── 8. system_health_checks + log checkpoints ───────────────────────────────
create table public.system_health_checks (
  id              uuid primary key default gen_random_uuid(),
  checked_at      timestamptz not null default now(),
  source          text not null,
  success         boolean not null,
  response_status integer,
  duration_ms     integer,
  details         jsonb not null default '{}'::jsonb
);
create index health_time_idx on public.system_health_checks (checked_at desc);

create table public.log_checkpoints (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  up_to       timestamptz not null,
  event_count bigint not null,
  digest      text not null,
  prev_digest text
);
create trigger checkpoints_append_only before update or delete on public.log_checkpoints
  for each row execute function public.protect_append_only();

-- ── authorization helpers ───────────────────────────────────────────────────
-- If an admin has a verified TOTP factor, only an aal2 (MFA-verified) session counts.
create or replace function public.mfa_satisfied(p_uid uuid, p_aal text) returns boolean
language sql stable security definer set search_path = public, auth as $$
  select coalesce(p_aal, 'aal1') = 'aal2'
      or not exists (select 1 from auth.mfa_factors f where f.user_id = p_uid and f.status = 'verified');
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admin_profiles p
    where p.id = auth.uid() and p.is_active
      and public.mfa_satisfied(p.id, auth.jwt() ->> 'aal'));
$$;

-- ── RLS ─────────────────────────────────────────────────────────────────────
do $$
declare t text;
begin
  foreach t in array array[
    'admin_profiles','devices','device_credentials','device_settings','security_events',
    'agent_integrity_events','device_heartbeats','device_commands','device_enrollment_tokens',
    'device_registration_history','device_auth_failures','agent_releases','app_settings',
    'admin_audit_logs','system_health_checks','log_checkpoints']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format('alter table public.%I force row level security', t);
  end loop;
  -- read-only policy for admins on everything the dashboard may see
  foreach t in array array[
    'devices','device_settings','security_events','agent_integrity_events','device_heartbeats',
    'device_commands','device_enrollment_tokens','device_registration_history','device_auth_failures',
    'agent_releases','app_settings','admin_audit_logs','system_health_checks','log_checkpoints']
  loop
    execute format('create policy "admins read" on public.%I for select to authenticated using (public.is_admin())', t);
  end loop;
end $$;

-- A signed-in user may read only their own profile row (so the UI can show "not authorized");
-- admins may read all profiles. Nobody can write from the browser.
create policy "own or admin read" on public.admin_profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
-- device_credentials: RLS on, no policy, no grants => only the service role can touch it.

-- ── privileges: deny by default, grant read-only where needed ───────────────
revoke all on all tables    in schema public from anon, authenticated;
revoke all on all functions in schema public from public, anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke execute on functions from public, anon, authenticated;

grant usage on schema public to authenticated;
grant select on public.admin_profiles, public.devices, public.device_settings, public.security_events,
  public.agent_integrity_events, public.device_heartbeats, public.device_commands,
  public.device_registration_history, public.device_auth_failures, public.agent_releases,
  public.app_settings, public.admin_audit_logs, public.system_health_checks, public.log_checkpoints
  to authenticated;
-- token_hash is never exposed
grant select (id,label,created_by,created_at,expires_at,used_at,used_by_device)
  on public.device_enrollment_tokens to authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.mfa_satisfied(uuid, text) to service_role;
grant execute on function public.is_admin() to service_role;

-- ── realtime (dashboard live refresh; RLS still applies) ────────────────────
alter publication supabase_realtime add table public.devices, public.security_events, public.device_commands;
