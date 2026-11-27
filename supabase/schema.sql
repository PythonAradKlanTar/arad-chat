-- ARAD CHAT starter schema. Apply in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  display_name text not null default 'کاربر',
  bio text not null default '',
  avatar_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('direct','group','channel')),
  title text,
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member',
  joined_at timestamptz not null default now(),
  primary key(conversation_id,user_id)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id),
  body text not null check (char_length(body) between 1 and 10000),
  created_at timestamptz not null default now()
);

create index if not exists messages_conversation_created_idx on public.messages(conversation_id,created_at);

alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

create policy "profiles visible to authenticated" on public.profiles for select to authenticated using (true);
create policy "users create own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
create policy "users update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy "members read conversations" on public.conversations for select to authenticated
using (exists(select 1 from public.conversation_members m where m.conversation_id=id and m.user_id=auth.uid()));
create policy "authenticated create conversation" on public.conversations for insert to authenticated
with check (created_by=auth.uid());
create policy "members read membership" on public.conversation_members for select to authenticated
using (exists(select 1 from public.conversation_members m where m.conversation_id=conversation_id and m.user_id=auth.uid()));
create policy "creator adds members" on public.conversation_members for insert to authenticated
with check (exists(select 1 from public.conversations c where c.id=conversation_id and c.created_by=auth.uid()));
create policy "members read messages" on public.messages for select to authenticated
using (exists(select 1 from public.conversation_members m where m.conversation_id=conversation_id and m.user_id=auth.uid()));
create policy "members send messages" on public.messages for insert to authenticated
with check (sender_id=auth.uid() and exists(select 1 from public.conversation_members m where m.conversation_id=conversation_id and m.user_id=auth.uid()));

-- Enable Realtime for messages in Dashboard > Database > Replication if not enabled automatically.
