-- Run after the migration on a Supabase-like database. Each block raises on failure.
\set ON_ERROR_STOP on
set client_min_messages = warning;
insert into auth.users(id) values ('00000000-0000-0000-0000-0000000000a1'),('00000000-0000-0000-0000-0000000000b2');
insert into public.admin_profiles(id,email,role) values ('00000000-0000-0000-0000-0000000000a1','a@x.com','owner');
insert into public.devices(id,device_name) values ('11111111-1111-1111-1111-111111111111','d1');
insert into public.device_credentials(device_id,secret_hash) values ('11111111-1111-1111-1111-111111111111','hash');
insert into public.device_settings(device_id) values ('11111111-1111-1111-1111-111111111111');
insert into public.security_events(device_id,event_type,category,severity,message,event_timestamp,deduplication_id)
  values ('11111111-1111-1111-1111-111111111111','t','login','low','m',now(),'x1');
insert into public.device_enrollment_tokens(token_hash,expires_at) values ('thash', now()+interval '1h');

-- 1. anonymous: nothing at all
set role anon;
do $$ begin
  begin perform count(*) from public.devices; raise exception 'anon could read devices'; exception when insufficient_privilege then null; end;
  begin perform count(*) from public.security_events; raise exception 'anon could read events'; exception when insufficient_privilege then null; end;
end $$;
reset role;

-- 2. authenticated but NOT an admin: RLS hides every row
set role authenticated; select set_config('request.jwt.claims','{"sub":"00000000-0000-0000-0000-0000000000b2","aal":"aal1"}',false);
do $$ begin
  if (select count(*) from public.devices) <> 0 then raise exception 'non-admin sees devices'; end if;
  if (select count(*) from public.security_events) <> 0 then raise exception 'non-admin sees events'; end if;
  if (select count(*) from public.admin_profiles) <> 0 then raise exception 'non-admin sees profiles'; end if;
end $$;
reset role;

-- 3. admin: read OK; no writes; secrets unreachable
set role authenticated; select set_config('request.jwt.claims','{"sub":"00000000-0000-0000-0000-0000000000a1","aal":"aal1"}',false);
do $$ begin
  if (select count(*) from public.devices) <> 1 then raise exception 'admin cannot read devices'; end if;
  if (select count(*) from public.security_events) <> 1 then raise exception 'admin cannot read events'; end if;
  begin insert into public.devices(device_name) values ('evil'); raise exception 'admin could insert device'; exception when insufficient_privilege then null; end;
  begin update public.devices set is_active=false; raise exception 'admin could update device'; exception when insufficient_privilege then null; end;
  begin delete from public.security_events; raise exception 'admin could delete events'; exception when insufficient_privilege then null; end;
  begin update public.admin_profiles set role='owner'; raise exception 'admin could change roles'; exception when insufficient_privilege then null; end;
  begin perform secret_hash from public.device_credentials; raise exception 'admin could read device secrets'; exception when insufficient_privilege then null; end;
  begin perform token_hash from public.device_enrollment_tokens; raise exception 'admin could read token hashes'; exception when insufficient_privilege then null; end;
  perform id, expires_at from public.device_enrollment_tokens;
end $$;
reset role;

-- 4. MFA: once a verified TOTP factor exists an aal1 session loses access; aal2 regains it
insert into auth.mfa_factors(user_id,status) values ('00000000-0000-0000-0000-0000000000a1','verified');
set role authenticated; select set_config('request.jwt.claims','{"sub":"00000000-0000-0000-0000-0000000000a1","aal":"aal1"}',false);
do $$ begin if (select count(*) from public.devices) <> 0 then raise exception 'aal1 session read data despite MFA'; end if; end $$;
select set_config('request.jwt.claims','{"sub":"00000000-0000-0000-0000-0000000000a1","aal":"aal2"}',false);
do $$ begin if (select count(*) from public.devices) <> 1 then raise exception 'aal2 session cannot read'; end if; end $$;
reset role;

-- 5. append-only triggers
do $$ begin
  begin delete from public.security_events; raise exception 'event delete allowed'; exception when raise_exception then if sqlerrm like '%allowed' then raise; end if; end;
  begin update public.security_events set message='tampered'; raise exception 'event edit allowed'; exception when raise_exception then if sqlerrm like '%allowed' then raise; end if; end;
  update public.security_events set resolved=true, resolved_at=now();
  insert into public.admin_audit_logs(action) values ('x');
  begin update public.admin_audit_logs set action='y'; raise exception 'audit edit allowed'; exception when raise_exception then if sqlerrm like '%allowed' then raise; end if; end;
  begin delete from public.admin_audit_logs; raise exception 'audit delete allowed'; exception when raise_exception then if sqlerrm like '%allowed' then raise; end if; end;
end $$;

-- 6. constraints
do $$ begin
  begin insert into public.security_events(device_id,event_type,category,severity,message,event_timestamp,deduplication_id) values ('11111111-1111-1111-1111-111111111111','t','login','low','m',now(),'x1'); raise exception 'dup allowed'; exception when unique_violation then null; end;
  begin insert into public.security_events(device_id,event_type,category,severity,message,event_timestamp,deduplication_id) values ('11111111-1111-1111-1111-111111111111','t','photo','low','m',now(),'x2'); raise exception 'bad category allowed'; exception when check_violation then null; end;
  begin insert into public.device_commands(device_id,command_type,expires_at) values ('11111111-1111-1111-1111-111111111111','format_disk',now()); raise exception 'bad command allowed'; exception when check_violation then null; end;
end $$;
-- 7. settings version bump
update public.device_settings set monitoring_enabled=false;
do $$ begin if (select settings_version from public.device_settings)<>2 then raise exception 'settings_version not bumped'; end if; end $$;
-- 8. RLS enabled + forced on every public table
do $$ declare t text; begin
  for t in select c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname='public' and c.relkind='r' and not (c.relrowsecurity and c.relforcerowsecurity) loop
    raise exception 'RLS not enforced on %', t; end loop; end $$;
select 'ALL RLS / INTEGRITY TESTS PASSED' as result;
