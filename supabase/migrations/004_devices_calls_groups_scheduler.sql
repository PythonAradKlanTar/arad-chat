-- ARAD CHAT v0.4: device inventory, group/channel controls, WebRTC signaling, server scheduler.
create extension if not exists pgcrypto;

-- App device inventory (not a raw Supabase Auth refresh-token/session dump).
alter table public.devices add column if not exists device_key text;
alter table public.devices add column if not exists user_agent text;
alter table public.devices add column if not exists platform text;
alter table public.devices add column if not exists is_current boolean not null default false;
create unique index if not exists devices_user_device_key_uq on public.devices(user_id,device_key);
alter table public.devices enable row level security;
drop policy if exists devices_self_access on public.devices;
create policy devices_self_read on public.devices for select to authenticated using(user_id=auth.uid());
create policy devices_self_insert on public.devices for insert to authenticated with check(user_id=auth.uid());
create policy devices_self_update on public.devices for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
create policy devices_self_delete on public.devices for delete to authenticated using(user_id=auth.uid());

-- A call room holds SDP; ICE candidates are separate rows. Realtime must be enabled for both tables.
create table if not exists public.call_sessions (
 id uuid primary key default gen_random_uuid(),
 conversation_id uuid not null references public.conversations(id) on delete cascade,
 caller_id uuid not null references auth.users(id) on delete cascade,
 callee_id uuid not null references auth.users(id) on delete cascade,
 call_type text not null check(call_type in ('audio','video')),
 offer jsonb,
 answer jsonb,
 status text not null default 'ringing' check(status in ('ringing','accepted','rejected','ended','missed')),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 check(caller_id<>callee_id)
);
create table if not exists public.call_ice_candidates (
 id uuid primary key default gen_random_uuid(),
 call_id uuid not null references public.call_sessions(id) on delete cascade,
 sender_id uuid not null references auth.users(id) on delete cascade,
 candidate jsonb not null,
 created_at timestamptz not null default now()
);
alter table public.call_sessions enable row level security;
alter table public.call_ice_candidates enable row level security;
create policy call_sessions_member_read on public.call_sessions for select to authenticated using(
 exists(select 1 from public.conversation_members cm where cm.conversation_id=call_sessions.conversation_id and cm.user_id=auth.uid())
);
create policy call_sessions_member_create on public.call_sessions for insert to authenticated with check(
 caller_id=auth.uid() and exists(select 1 from public.conversation_members cm where cm.conversation_id=call_sessions.conversation_id and cm.user_id=auth.uid()) and exists(select 1 from public.conversation_members cm where cm.conversation_id=call_sessions.conversation_id and cm.user_id=callee_id)
);
create policy call_sessions_participant_update on public.call_sessions for update to authenticated using(auth.uid() in (caller_id,callee_id)) with check(auth.uid() in (caller_id,callee_id));
create policy call_ice_read_participant on public.call_ice_candidates for select to authenticated using(exists(select 1 from public.call_sessions c where c.id=call_id and auth.uid() in(c.caller_id,c.callee_id)));
create policy call_ice_insert_participant on public.call_ice_candidates for insert to authenticated with check(sender_id=auth.uid() and exists(select 1 from public.call_sessions c where c.id=call_id and auth.uid() in(c.caller_id,c.callee_id)));

do $$ begin
 if exists(select 1 from pg_publication where pubname='supabase_realtime') then
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='call_sessions') then alter publication supabase_realtime add table public.call_sessions; end if;
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='call_ice_candidates') then alter publication supabase_realtime add table public.call_ice_candidates; end if;
 end if;
end $$;

-- Membership and metadata changes are server-checked by SECURITY DEFINER RPCs.
create or replace function public.manage_conversation_member(p_conversation_id uuid,p_user_id uuid,p_action text)
returns void language plpgsql security definer set search_path=public as $$
declare v_kind text; v_role text; v_owner uuid;
begin
 if auth.uid() is null then raise exception 'authentication required'; end if;
 select c.kind,c.created_by,cm.role into v_kind,v_owner,v_role from conversations c left join conversation_members cm on cm.conversation_id=c.id and cm.user_id=auth.uid() where c.id=p_conversation_id;
 if not found then raise exception 'conversation not found'; end if;
 if auth.uid()<>v_owner and coalesce(v_role,'') not in ('owner','admin') then raise exception 'admin permission required'; end if;
 if p_action='add' then
  insert into conversation_members(conversation_id,user_id,role) values(p_conversation_id,p_user_id,'member') on conflict do nothing;
 elsif p_action='remove' then
  if p_user_id=v_owner then raise exception 'cannot remove creator'; end if;
  delete from conversation_members where conversation_id=p_conversation_id and user_id=p_user_id;
 elsif p_action='promote' then
  update conversation_members set role='admin' where conversation_id=p_conversation_id and user_id=p_user_id;
 elsif p_action='demote' then
  update conversation_members set role='member' where conversation_id=p_conversation_id and user_id=p_user_id;
 else raise exception 'unsupported action'; end if;
 insert into admin_group_actions(conversation_id,actor_id,action,details) values(p_conversation_id,auth.uid(),p_action,jsonb_build_object('user_id',p_user_id));
end $$;
revoke all on function public.manage_conversation_member(uuid,uuid,text) from public;
grant execute on function public.manage_conversation_member(uuid,uuid,text) to authenticated;

create or replace function public.update_conversation_details(p_conversation_id uuid,p_title text,p_description text)
returns void language plpgsql security definer set search_path=public as $$
declare v_owner uuid; v_role text;
begin
 select created_by into v_owner from conversations where id=p_conversation_id;
 select role into v_role from conversation_members where conversation_id=p_conversation_id and user_id=auth.uid();
 if auth.uid() is null or (auth.uid()<>v_owner and coalesce(v_role,'') not in ('owner','admin')) then raise exception 'admin permission required'; end if;
 update conversations set title=left(coalesce(p_title,''),100),description=left(coalesce(p_description,''),2000) where id=p_conversation_id;
end $$;
revoke all on function public.update_conversation_details(uuid,text,text) from public;
grant execute on function public.update_conversation_details(uuid,text,text) to authenticated;

-- Only group/channel owner/admin can post in a channel; all group members can post in groups.
drop policy if exists "members send messages" on public.messages;
create policy "members send messages" on public.messages for insert to authenticated with check(
 sender_id=auth.uid() and exists(
  select 1 from public.conversation_members cm join public.conversations c on c.id=cm.conversation_id
  where cm.conversation_id=messages.conversation_id and cm.user_id=auth.uid()
  and (c.kind<>'channel' or cm.role in ('owner','admin') or c.created_by=auth.uid())
 )
);

-- Server-side scheduled dispatch. pg_cron executes every minute, even when browsers are closed.
create or replace function public.dispatch_scheduled_messages()
returns integer language plpgsql security definer set search_path=public as $$
declare item record; n integer:=0;
begin
 for item in
  select sm.* from scheduled_messages sm
  where sm.sent_at is null and sm.send_at<=now()
  order by sm.send_at
  for update skip locked limit 100
 loop
  if exists(select 1 from conversation_members cm where cm.conversation_id=item.conversation_id and cm.user_id=item.sender_id) then
   insert into messages(conversation_id,sender_id,body) values(item.conversation_id,item.sender_id,item.body);
   update scheduled_messages set sent_at=now() where id=item.id;
   n:=n+1;
  else
   update scheduled_messages set sent_at=now() where id=item.id;
  end if;
 end loop;
 return n;
end $$;
revoke all on function public.dispatch_scheduled_messages() from public,anon,authenticated;

-- Optional extension: if pg_cron is available on this Supabase project, schedule it automatically.
do $$ begin
 create extension if not exists pg_cron with schema pg_catalog;
 if exists(select 1 from pg_extension where extname='pg_cron') then
  perform cron.unschedule(jobid) from cron.job where jobname='arad-chat-scheduled-dispatch';
  perform cron.schedule('arad-chat-scheduled-dispatch','* * * * *','select public.dispatch_scheduled_messages();');
 end if;
exception when others then
 raise notice 'pg_cron unavailable; deploy scheduled-dispatch Edge Function and configure Supabase Cron instead. Detail: %',sqlerrm;
end $$;

create index if not exists scheduled_due_idx on public.scheduled_messages(send_at) where sent_at is null;
create index if not exists call_sessions_callee_idx on public.call_sessions(callee_id,status,created_at desc);

-- Lock call participant identity and restrict who can transition a call.
create or replace function public.guard_call_session_update()
returns trigger language plpgsql security invoker set search_path=public as $$
begin
 if new.conversation_id<>old.conversation_id or new.caller_id<>old.caller_id or new.callee_id<>old.callee_id or new.call_type<>old.call_type or new.offer is distinct from old.offer then
  raise exception 'call identity and offer are immutable';
 end if;
 if auth.uid()=old.caller_id then
  if new.answer is distinct from old.answer or new.status not in ('ended') then raise exception 'caller may only end the call'; end if;
 elsif auth.uid()=old.callee_id then
  if new.answer is distinct from old.answer and old.answer is not null then raise exception 'answer already set'; end if;
  if new.status not in ('accepted','rejected','ended') then raise exception 'callee cannot set this status'; end if;
 else
  raise exception 'not a call participant';
 end if;
 new.updated_at=now();
 return new;
end $$;
drop trigger if exists call_session_guard on public.call_sessions;
create trigger call_session_guard before update on public.call_sessions for each row execute function public.guard_call_session_update();

-- Also deny new message writes for currently banned accounts, including already-issued JWTs.
drop policy if exists "members send messages" on public.messages;
create policy "members send messages" on public.messages for insert to authenticated with check(
 sender_id=auth.uid()
 and not exists(select 1 from public.user_bans b where b.user_id=auth.uid() and (b.expires_at is null or b.expires_at>now()))
 and exists(
  select 1 from public.conversation_members cm join public.conversations c on c.id=cm.conversation_id
  where cm.conversation_id=messages.conversation_id and cm.user_id=auth.uid()
  and (c.kind<>'channel' or cm.role in ('owner','admin') or c.created_by=auth.uid())
 )
);
