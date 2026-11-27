-- ARAD CHAT admin / owner foundation.
-- SECURITY: all these tables intentionally have RLS enabled with no client policies.
-- Manage them only through trusted Edge Functions after verifying the owner/admin role.

create table if not exists public.staff_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','moderator')),
  granted_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.admin_permissions (
  role text not null check (role in ('admin','moderator')),
  permission text not null,
  primary key(role, permission)
);

create table if not exists public.admin_user_actions (
  id uuid primary key default gen_random_uuid(),
  target_user_id uuid not null references auth.users(id) on delete cascade,
  actor_id uuid not null references auth.users(id),
  action text not null check (action in ('ban_temp','ban_permanent','unban','verify_grant','verify_revoke','premium_grant','premium_revoke')),
  reason text,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.admin_announcements (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references auth.users(id),
  title text not null,
  body text not null,
  audience text not null default 'all' check (audience in ('all','active','premium')),
  status text not null default 'draft' check (status in ('draft','queued','sent','cancelled')),
  scheduled_at timestamptz,
  sent_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.admin_settings (
  key text primary key,
  value jsonb not null,
  updated_by uuid references auth.users(id),
  updated_at timestamptz not null default now()
);

create table if not exists public.bot_store_listings (
  id uuid primary key default gen_random_uuid(),
  bot_id uuid not null references public.bots(id) on delete cascade,
  submitted_by uuid not null references auth.users(id),
  status text not null default 'pending' check (status in ('pending','approved','rejected','disabled')),
  category text not null default 'general',
  reviewed_by uuid references auth.users(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  unique(bot_id)
);

create table if not exists public.admin_group_actions (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  actor_id uuid not null references auth.users(id),
  action text not null,
  reason text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.file_asset_metadata (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid references auth.users(id) on delete set null,
  conversation_id uuid references public.conversations(id) on delete set null,
  storage_path text not null unique,
  mime_type text,
  byte_size bigint not null default 0 check(byte_size >= 0),
  created_at timestamptz not null default now()
);

-- Useful indexes for admin moderation queues and dashboard reports.
create index if not exists reports_status_created_idx on public.reports(status, created_at desc);
create index if not exists admin_audit_logs_created_idx on public.admin_audit_logs(created_at desc);
create index if not exists admin_user_actions_target_idx on public.admin_user_actions(target_user_id, created_at desc);
create index if not exists admin_announcements_status_idx on public.admin_announcements(status, scheduled_at);
create index if not exists bot_store_status_idx on public.bot_store_listings(status, created_at desc);
create index if not exists file_asset_created_idx on public.file_asset_metadata(created_at desc);

alter table public.staff_roles enable row level security;
alter table public.admin_permissions enable row level security;
alter table public.admin_user_actions enable row level security;
alter table public.admin_announcements enable row level security;
alter table public.admin_settings enable row level security;
alter table public.bot_store_listings enable row level security;
alter table public.admin_group_actions enable row level security;
alter table public.file_asset_metadata enable row level security;

-- Do NOT create an owner by inserting a public fixed password or client-side flag.
-- Bootstrap the first owner through a trusted, one-time server-side process after
-- confirming the account identity. Never expose the Supabase service_role key.
