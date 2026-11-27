-- ARAD CHAT: free-tier feature expansion. Run after all previous SQL files.
create extension if not exists pgcrypto;

alter table public.messages add column if not exists reply_to uuid references public.messages(id) on delete set null;
alter table public.messages add column if not exists forwarded_from uuid references public.messages(id) on delete set null;
alter table public.messages add column if not exists edited_at timestamptz;
alter table public.messages add column if not exists deleted_at timestamptz;
alter table public.messages add column if not exists attachment_path text;
alter table public.messages add column if not exists attachment_name text;
alter table public.messages add column if not exists attachment_mime text;
alter table public.messages add column if not exists message_type text not null default 'text';
alter table public.conversation_members add column if not exists is_archived boolean not null default false;
alter table public.conversation_members add column if not exists is_pinned boolean not null default false;
alter table public.conversations add column if not exists description text not null default '';
alter table public.conversations add column if not exists photo_url text;

create table if not exists public.contact_requests (
  id uuid primary key default gen_random_uuid(), sender_id uuid not null references auth.users(id) on delete cascade,
  receiver_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check(status in ('pending','accepted','rejected')),
  created_at timestamptz not null default now(), unique(sender_id,receiver_id), check(sender_id <> receiver_id)
);
create table if not exists public.conversation_reads (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  last_read_at timestamptz not null default now(), primary key(conversation_id,user_id)
);
create table if not exists public.story_views (
  story_id uuid not null references public.stories(id) on delete cascade,
  viewer_id uuid not null references auth.users(id) on delete cascade,
  viewed_at timestamptz not null default now(), primary key(story_id,viewer_id)
);
create table if not exists public.poll_options (
  poll_id uuid not null references public.polls(id) on delete cascade,
  option_index int not null,
  option_text text not null,
  primary key(poll_id,option_index)
);
create table if not exists public.user_blocks (
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(), primary key(blocker_id,blocked_id), check(blocker_id <> blocked_id)
);

-- RLS: users can only mutate their own contact/settings/story data.
alter table public.contacts enable row level security;
drop policy if exists contacts_read_own on public.contacts;
create policy contacts_read_own on public.contacts for select to authenticated using(owner_id=auth.uid());
drop policy if exists contacts_insert_own on public.contacts;
create policy contacts_insert_own on public.contacts for insert to authenticated with check(owner_id=auth.uid() and contact_id<>auth.uid());
drop policy if exists contacts_delete_own on public.contacts;
create policy contacts_delete_own on public.contacts for delete to authenticated using(owner_id=auth.uid());

alter table public.message_reactions enable row level security;
drop policy if exists reactions_read_members on public.message_reactions;
create policy reactions_read_members on public.message_reactions for select to authenticated using(exists(select 1 from public.messages x join public.conversation_members cm on cm.conversation_id=x.conversation_id where x.id=message_id and cm.user_id=auth.uid()));
drop policy if exists reactions_insert_self on public.message_reactions;
create policy reactions_insert_self on public.message_reactions for insert to authenticated with check(user_id=auth.uid() and exists(select 1 from public.messages x join public.conversation_members cm on cm.conversation_id=x.conversation_id where x.id=message_id and cm.user_id=auth.uid()));
drop policy if exists reactions_delete_self on public.message_reactions;
create policy reactions_delete_self on public.message_reactions for delete to authenticated using(user_id=auth.uid());

alter table public.saved_messages enable row level security;
drop policy if exists saved_read_self on public.saved_messages;
create policy saved_read_self on public.saved_messages for select to authenticated using(user_id=auth.uid());
drop policy if exists saved_insert_self on public.saved_messages;
create policy saved_insert_self on public.saved_messages for insert to authenticated with check(user_id=auth.uid() and exists(select 1 from public.messages x join public.conversation_members cm on cm.conversation_id=x.conversation_id where x.id=message_id and cm.user_id=auth.uid()));
drop policy if exists saved_delete_self on public.saved_messages;
create policy saved_delete_self on public.saved_messages for delete to authenticated using(user_id=auth.uid());

alter table public.message_pins enable row level security;
drop policy if exists pins_read_members on public.message_pins;
create policy pins_read_members on public.message_pins for select to authenticated using(exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));
drop policy if exists pins_insert_members on public.message_pins;
create policy pins_insert_members on public.message_pins for insert to authenticated with check(pinned_by=auth.uid() and exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));
drop policy if exists pins_delete_self on public.message_pins;
create policy pins_delete_self on public.message_pins for delete to authenticated using(pinned_by=auth.uid());

alter table public.stories enable row level security;
drop policy if exists stories_read_auth on public.stories;
create policy stories_read_auth on public.stories for select to authenticated using(expires_at>now());
drop policy if exists stories_insert_self on public.stories;
create policy stories_insert_self on public.stories for insert to authenticated with check(user_id=auth.uid());
drop policy if exists stories_delete_self on public.stories;
create policy stories_delete_self on public.stories for delete to authenticated using(user_id=auth.uid());

alter table public.polls enable row level security;
drop policy if exists polls_read_members on public.polls;
create policy polls_read_members on public.polls for select to authenticated using(exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));
drop policy if exists polls_insert_members on public.polls;
create policy polls_insert_members on public.polls for insert to authenticated with check(created_by=auth.uid() and exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));
alter table public.poll_votes enable row level security;
drop policy if exists votes_read_members on public.poll_votes;
create policy votes_read_members on public.poll_votes for select to authenticated using(exists(select 1 from public.polls p join public.conversation_members cm on cm.conversation_id=p.conversation_id where p.id=poll_id and cm.user_id=auth.uid()));
drop policy if exists votes_insert_self on public.poll_votes;
create policy votes_insert_self on public.poll_votes for insert to authenticated with check(user_id=auth.uid() and exists(select 1 from public.polls p join public.conversation_members cm on cm.conversation_id=p.conversation_id where p.id=poll_id and cm.user_id=auth.uid()));

alter table public.scheduled_messages enable row level security;
drop policy if exists scheduled_read_self on public.scheduled_messages;
create policy scheduled_read_self on public.scheduled_messages for select to authenticated using(sender_id=auth.uid());
drop policy if exists scheduled_insert_self on public.scheduled_messages;
create policy scheduled_insert_self on public.scheduled_messages for insert to authenticated with check(sender_id=auth.uid() and exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));
drop policy if exists scheduled_delete_self on public.scheduled_messages;
create policy scheduled_delete_self on public.scheduled_messages for delete to authenticated using(sender_id=auth.uid());

alter table public.reports enable row level security;
drop policy if exists reports_insert_self on public.reports;
create policy reports_insert_self on public.reports for insert to authenticated with check(reporter_id=auth.uid());

alter table public.user_settings enable row level security;
drop policy if exists settings_read_self on public.user_settings;
create policy settings_read_self on public.user_settings for select to authenticated using(user_id=auth.uid());
drop policy if exists settings_write_self on public.user_settings;
create policy settings_write_self on public.user_settings for all to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());

alter table public.user_blocks enable row level security;
drop policy if exists blocks_self on public.user_blocks;
create policy blocks_self on public.user_blocks for all to authenticated using(blocker_id=auth.uid()) with check(blocker_id=auth.uid() and blocked_id<>auth.uid());

-- Storage bucket. Files are private; path convention: <auth.uid()>/<conversation-id>/<filename>.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('arad-media','arad-media',false,52428800,array['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','audio/webm','audio/ogg','audio/mpeg','audio/mp4','application/pdf','text/plain','application/zip'])
on conflict(id) do update set public=false, file_size_limit=52428800, allowed_mime_types=excluded.allowed_mime_types;
drop policy if exists arad_media_upload_own on storage.objects;
create policy arad_media_upload_own on storage.objects for insert to authenticated with check(bucket_id='arad-media' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists arad_media_read_auth on storage.objects;
create policy arad_media_read_auth on storage.objects for select to authenticated using(bucket_id='arad-media' and (storage.foldername(name))[1]=auth.uid()::text);
drop policy if exists arad_media_delete_own on storage.objects;
create policy arad_media_delete_own on storage.objects for delete to authenticated using(bucket_id='arad-media' and (storage.foldername(name))[1]=auth.uid()::text);

create index if not exists contacts_owner_idx on public.contacts(owner_id);
create index if not exists stories_expiry_idx on public.stories(expires_at);
create index if not exists reactions_message_idx on public.message_reactions(message_id);
create index if not exists polls_conversation_idx on public.polls(conversation_id,created_at desc);

-- Note: push, WebRTC TURN, scheduled workers, automatic expiry and bot sandboxing need external runtime/configuration.
-- Message editing/deletion and per-user conversation preferences.
drop policy if exists messages_update_own on public.messages;
create policy messages_update_own on public.messages for update to authenticated using(sender_id=auth.uid()) with check(sender_id=auth.uid());
drop policy if exists messages_delete_own on public.messages;
create policy messages_delete_own on public.messages for delete to authenticated using(sender_id=auth.uid());
drop policy if exists members_update_self on public.conversation_members;
create policy members_update_self on public.conversation_members for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());

-- Conversation creators can manage title/description; actual member-role moderation should use a trusted function.
drop policy if exists conversations_update_creator on public.conversations;
create policy conversations_update_creator on public.conversations for update to authenticated using(created_by=auth.uid()) with check(created_by=auth.uid());
-- Allow recipients in the same conversation to download private attachments.
drop policy if exists arad_media_read_auth on storage.objects;
create policy arad_media_read_auth on storage.objects for select to authenticated
using(bucket_id='arad-media' and (
  (storage.foldername(name))[1]=auth.uid()::text
  or (coalesce((storage.foldername(name))[2],'') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' and exists(select 1 from public.conversation_members cm where cm.conversation_id=((storage.foldername(name))[2])::uuid and cm.user_id=auth.uid()))
));
alter table public.story_views enable row level security;
drop policy if exists story_views_insert_self on public.story_views;
create policy story_views_insert_self on public.story_views for insert to authenticated with check(viewer_id=auth.uid());
drop policy if exists story_views_read_story_owner on public.story_views;
create policy story_views_read_story_owner on public.story_views for select to authenticated using(exists(select 1 from public.stories s where s.id=story_id and (s.user_id=auth.uid() or s.expires_at>now())));

drop policy if exists staff_roles_read_self on public.staff_roles;
create policy staff_roles_read_self on public.staff_roles for select to authenticated using(user_id=auth.uid());

drop policy if exists arad_media_read_auth on storage.objects;
create policy arad_media_read_auth on storage.objects for select to authenticated
using(bucket_id='arad-media' and (
  (storage.foldername(name))[1]=auth.uid()::text
  or exists(select 1 from public.stories s where s.media_path=name and s.expires_at>now())
  or (coalesce((storage.foldername(name))[2],'') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' and exists(select 1 from public.conversation_members cm where cm.conversation_id=((storage.foldername(name))[2])::uuid and cm.user_id=auth.uid()))
));
alter table public.messages add column if not exists expires_at timestamptz;
drop policy if exists "members read messages" on public.messages;
create policy "members read messages" on public.messages for select to authenticated
using(exists(select 1 from public.conversation_members m where m.conversation_id=conversation_id and m.user_id=auth.uid()) and (expires_at is null or expires_at>now()));
alter table public.disappearing_settings enable row level security;
drop policy if exists disappearing_member_access on public.disappearing_settings;
create policy disappearing_member_access on public.disappearing_settings for all to authenticated
using(exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()))
with check(changed_by=auth.uid() and exists(select 1 from public.conversation_members cm where cm.conversation_id=conversation_id and cm.user_id=auth.uid()));

drop policy if exists scheduled_update_self on public.scheduled_messages;
create policy scheduled_update_self on public.scheduled_messages for update to authenticated using(sender_id=auth.uid()) with check(sender_id=auth.uid());
drop policy if exists reactions_update_self on public.message_reactions;
create policy reactions_update_self on public.message_reactions for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
drop policy if exists pins_update_self on public.message_pins;
create policy pins_update_self on public.message_pins for update to authenticated using(pinned_by=auth.uid()) with check(pinned_by=auth.uid());
drop policy if exists story_views_update_self on public.story_views;
create policy story_views_update_self on public.story_views for update to authenticated using(viewer_id=auth.uid()) with check(viewer_id=auth.uid());
drop policy if exists votes_update_self on public.poll_votes;
create policy votes_update_self on public.poll_votes for update to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
alter table public.devices enable row level security;
drop policy if exists devices_self_access on public.devices;
create policy devices_self_access on public.devices for all to authenticated using(user_id=auth.uid()) with check(user_id=auth.uid());
