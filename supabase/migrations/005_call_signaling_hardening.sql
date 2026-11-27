-- ARAD CHAT v0.5 hardening for WebRTC call signaling.
-- Apply after migrations 001-004 and the base/admin schemas.

create or replace function public.guard_call_session_updates()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare
  actor uuid := auth.uid();
begin
  if actor is null then
    raise exception 'authentication required';
  end if;
  if new.id <> old.id
     or new.conversation_id <> old.conversation_id
     or new.caller_id <> old.caller_id
     or new.callee_id <> old.callee_id
     or new.call_type <> old.call_type
     or new.offer is distinct from old.offer
     or new.created_at <> old.created_at then
    raise exception 'immutable call fields cannot be changed';
  end if;

  if actor not in (old.caller_id, old.callee_id) then
    raise exception 'call participant required';
  end if;

  if new.answer is distinct from old.answer and actor <> old.callee_id then
    raise exception 'only callee may submit answer';
  end if;

  if new.status is distinct from old.status then
    if old.status <> 'ringing' and new.status in ('accepted','rejected','missed','ringing') then
      raise exception 'invalid call status transition';
    end if;
    if new.status in ('accepted','rejected') and actor <> old.callee_id then
      raise exception 'only callee may accept or reject';
    end if;
    if new.status = 'missed' and actor <> old.caller_id then
      raise exception 'only caller may mark call missed';
    end if;
    if new.status = 'ended' and (actor not in (old.caller_id, old.callee_id) or old.status not in ('ringing','accepted')) then
      raise exception 'participant cannot end this call state';
    end if;
    if new.status not in ('accepted','rejected','ended','missed','ringing') then
      raise exception 'invalid call status';
    end if;
  end if;

  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists call_session_update_guard on public.call_sessions;
create trigger call_session_update_guard
before update on public.call_sessions
for each row execute function public.guard_call_session_updates();

-- Do not expose call signaling rows to anonymous users.
revoke all on public.call_sessions from anon;
revoke all on public.call_ice_candidates from anon;
grant select, insert, update on public.call_sessions to authenticated;
grant select, insert on public.call_ice_candidates to authenticated;
