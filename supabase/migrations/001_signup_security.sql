-- Run after schema.sql. Auth users are unique by email in Supabase Auth.
-- This migration adds case-insensitive unique usernames and verified-email guard.
create unique index if not exists profiles_username_lower_uidx on public.profiles (lower(username));

create or replace function public.require_verified_email_for_profile()
returns trigger language plpgsql security definer set search_path = public, auth as $$
declare confirmed_at timestamptz;
begin
  select email_confirmed_at into confirmed_at from auth.users where id = new.id;
  if confirmed_at is null then
    raise exception 'Email must be verified before profile creation';
  end if;
  new.username := lower(regexp_replace(new.username, '^@', ''));
  if new.username !~ '^[a-z0-9_]{3,24}$' then
    raise exception 'Username must be 3-24 characters: a-z, 0-9, underscore';
  end if;
  return new;
end;
$$;
drop trigger if exists profiles_verified_email_guard on public.profiles;
create trigger profiles_verified_email_guard before insert or update of username on public.profiles
for each row execute function public.require_verified_email_for_profile();
