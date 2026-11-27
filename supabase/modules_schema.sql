-- Additional ARAD CHAT modules (schema foundation; server-side workflows still required)
create table if not exists public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  theme text not null default 'dark' check (theme in ('dark','light')),
  two_factor_enabled boolean not null default false,
  updated_at timestamptz not null default now()
);
create table if not exists public.contacts (
  owner_id uuid not null references auth.users(id) on delete cascade,
  contact_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(owner_id,contact_id), check(owner_id <> contact_id)
);
create table if not exists public.message_reactions (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  emoji text not null,
  created_at timestamptz not null default now(),
  primary key(message_id,user_id,emoji)
);
create table if not exists public.message_pins (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  message_id uuid not null references public.messages(id) on delete cascade,
  pinned_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  primary key(conversation_id,message_id)
);
create table if not exists public.saved_messages (
  user_id uuid not null references auth.users(id) on delete cascade,
  message_id uuid not null references public.messages(id) on delete cascade,
  saved_at timestamptz not null default now(),
  primary key(user_id,message_id)
);
create table if not exists public.stories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  media_path text not null,
  caption text default '',
  expires_at timestamptz not null default now() + interval '24 hours',
  created_at timestamptz not null default now()
);
create table if not exists public.polls (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  created_by uuid not null references auth.users(id),
  question text not null,
  options jsonb not null,
  closes_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.poll_votes (
  poll_id uuid not null references public.polls(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  option_index integer not null,
  created_at timestamptz not null default now(),
  primary key(poll_id,user_id)
);
create table if not exists public.scheduled_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null,
  send_at timestamptz not null,
  sent_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.disappearing_settings (
  conversation_id uuid primary key references public.conversations(id) on delete cascade,
  seconds integer not null check(seconds in (60,3600,86400,604800)),
  changed_by uuid not null references auth.users(id),
  updated_at timestamptz not null default now()
);
create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid references auth.users(id) on delete set null,
  target_user_id uuid references auth.users(id) on delete set null,
  target_message_id uuid references public.messages(id) on delete set null,
  reason text not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);
create table if not exists public.user_bans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  issued_by uuid not null references auth.users(id),
  reason text not null,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.user_entitlements (
  user_id uuid primary key references auth.users(id) on delete cascade,
  is_premium boolean not null default false,
  is_verified boolean not null default false,
  premium_until timestamptz,
  granted_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);
create table if not exists public.devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  label text,
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create table if not exists public.invite_codes (
  code text primary key,
  created_by uuid references auth.users(id),
  max_uses integer not null default 1,
  used_count integer not null default 0,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.bots (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  username text unique not null,
  display_name text not null,
  description text default '',
  is_active boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.bot_commands (
  id uuid primary key default gen_random_uuid(),
  bot_id uuid not null references public.bots(id) on delete cascade,
  command text not null,
  response text not null,
  unique(bot_id,command)
);
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text not null,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.admin_audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references auth.users(id),
  action text not null,
  target_user_id uuid references auth.users(id),
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- IMPORTANT: Do not enable public access to these tables blindly.
-- Apply per-table RLS and privileged admin operations through Edge Functions
-- after defining the owner identity and authorization model.
