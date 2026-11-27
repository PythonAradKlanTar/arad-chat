-- OWNER BOOTSTRAP — run once in Supabase SQL Editor after creating your account.
-- 1) Register/sign in to ARAD CHAT with the email you will use as owner.
-- 2) Verify that email in Supabase Auth.
-- 3) Replace the email below with that exact email and run this query.
-- Never put a service-role key or owner password in frontend code.
insert into public.staff_roles (user_id, role, granted_by)
select id, 'owner', id
from auth.users
where lower(email) = lower('arezopourahmad902@gmail.com')
  and email_confirmed_at is not null
on conflict (user_id) do update
set role = 'owner', granted_by = excluded.granted_by;

-- Confirm that exactly the intended account is marked owner:
select u.id, u.email, u.email_confirmed_at, r.role
from auth.users u
join public.staff_roles r on r.user_id = u.id
where r.role = 'owner';
