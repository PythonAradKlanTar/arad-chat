-- ARAD CHAT v0.3 free-tier fixes. Run after migrations 001 and 002.
-- Prevent users from changing their own membership role through a broad UPDATE policy.
drop policy if exists members_update_self on public.conversation_members;

create or replace function public.set_conversation_preference(
  p_conversation_id uuid,
  p_field text,
  p_value boolean
) returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'authentication required';
  end if;
  if not exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = p_conversation_id and cm.user_id = auth.uid()
  ) then
    raise exception 'not a conversation member';
  end if;
  if p_field = 'is_archived' then
    update public.conversation_members
      set is_archived = p_value
      where conversation_id = p_conversation_id and user_id = auth.uid();
  elsif p_field = 'is_pinned' then
    update public.conversation_members
      set is_pinned = p_value
      where conversation_id = p_conversation_id and user_id = auth.uid();
  else
    raise exception 'unsupported preference';
  end if;
end;
$$;
revoke all on function public.set_conversation_preference(uuid,text,boolean) from public;
grant execute on function public.set_conversation_preference(uuid,text,boolean) to authenticated;

-- Reports can identify the conversation being reported without exposing reports to clients.
alter table public.reports add column if not exists target_conversation_id uuid references public.conversations(id) on delete set null;

-- Ensure messages are in the Realtime publication when it exists.
do $$
begin
  if exists(select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;

create index if not exists messages_expiry_idx on public.messages(expires_at) where expires_at is not null;
create index if not exists conversations_kind_created_idx on public.conversations(kind, created_at desc);

-- Let users add metadata only for their own uploaded objects; admin dashboards read via service role.
drop policy if exists file_asset_metadata_insert_owner on public.file_asset_metadata;
create policy file_asset_metadata_insert_owner on public.file_asset_metadata
for insert to authenticated with check (
  owner_id = auth.uid()
  and exists (
    select 1 from storage.objects o
    where o.bucket_id = 'arad-media' and o.name = storage_path
      and (storage.foldername(o.name))[1] = auth.uid()::text
  )
  and (conversation_id is null or exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = file_asset_metadata.conversation_id and cm.user_id = auth.uid()
  ))
);
