-- Rudrakrit role-based access migration
-- Run this entire script in Supabase Dashboard -> SQL Editor.
begin;

create table if not exists public.team_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','editor','client')),
  email text,
  client_name text,
  created_at timestamptz not null default now(),
  constraint client_role_has_name check (role <> 'client' or nullif(btrim(client_name),'') is not null)
);

alter table public.team_members enable row level security;
alter table public.team_members add column if not exists email text;
drop policy if exists "team members read own" on public.team_members;
drop policy if exists "team members owner manage" on public.team_members;
create or replace function public.is_team_owner()
returns boolean language sql stable security definer
set search_path = public, auth
as $$
  select exists (select 1 from public.team_members where user_id=auth.uid() and role='owner')
$$;
grant execute on function public.is_team_owner() to authenticated;

create policy "team members read own" on public.team_members
for select to authenticated using (user_id = auth.uid());
create policy "team members owner manage" on public.team_members
for all to authenticated using (public.is_team_owner())
with check (public.is_team_owner());
grant select, insert, update, delete on public.team_members to authenticated;

create or replace function public.current_team_role()
returns text language sql stable security definer
set search_path = public, auth
as $$
  select role from public.team_members where user_id = auth.uid()
$$;

create or replace function public.current_client_name()
returns text language sql stable security definer
set search_path = public, auth
as $$
  select client_name from public.team_members where user_id = auth.uid() and role='client'
$$;

grant execute on function public.current_team_role() to authenticated;
grant execute on function public.current_client_name() to authenticated;

alter table public.videos enable row level security;
alter table public.videos add column if not exists editor_id uuid references auth.users(id) on delete set null;

drop policy if exists "team read" on public.videos;
drop policy if exists "team insert" on public.videos;
drop policy if exists "team update" on public.videos;
drop policy if exists "team delete" on public.videos;
drop policy if exists "videos_select_by_role" on public.videos;
drop policy if exists "videos_insert_by_role" on public.videos;
drop policy if exists "videos_update_by_role" on public.videos;
drop policy if exists "videos_delete_by_role" on public.videos;

create policy "videos_select_by_role" on public.videos
for select to authenticated
using (
  public.current_team_role() in ('owner','editor')
  or (public.current_team_role()='client' and client = public.current_client_name())
);

create policy "videos_insert_by_role" on public.videos
for insert to authenticated
with check (
  public.current_team_role()='owner'
  or (public.current_team_role()='editor' and editor_id=auth.uid())
);

create policy "videos_update_by_role" on public.videos
for update to authenticated
using (
  public.current_team_role()='owner'
  or (public.current_team_role()='editor' and editor_id=auth.uid())
)
with check (
  public.current_team_role()='owner'
  or (public.current_team_role()='editor' and editor_id=auth.uid())
);

create policy "videos_delete_by_role" on public.videos
for delete to authenticated
using (
  public.current_team_role()='owner'
  or (public.current_team_role()='editor' and editor_id=auth.uid())
);

grant select, insert, update, delete on public.videos to authenticated;

create or replace function public.claim_video(p_video_id text)
returns void language plpgsql security definer
set search_path = public, auth
as $$
declare v_name text;
begin
  if public.current_team_role() <> 'editor' then
    raise exception 'Only editors can claim videos';
  end if;
  select coalesce(nullif(raw_user_meta_data->>'name',''), split_part(email,'@',1))
    into v_name from auth.users where id=auth.uid();
  update public.videos
     set editor_id=auth.uid(), editor_name=initcap(v_name), status='Editing'
   where id::text=p_video_id and editor_id is null;
  if not found then raise exception 'This video is already assigned or unavailable'; end if;
end;
$$;
grant execute on function public.claim_video(text) to authenticated;

create or replace function public.release_video(p_video_id text)
returns void language plpgsql security definer
set search_path = public, auth
as $$
begin
  if public.current_team_role() <> 'editor' then
    raise exception 'Only editors can release their own videos';
  end if;
  update public.videos
     set editor_id=null, editor_name=null, status='Pending'
   where id::text=p_video_id and editor_id=auth.uid();
  if not found then raise exception 'This video is not assigned to your account'; end if;
end;
$$;
grant execute on function public.release_video(text) to authenticated;

-- Stop rather than silently assigning only a subset of the intended accounts.
do $$
begin
  if (
    select count(*) from auth.users
    where lower(email) in (
      lower('dhavaljoshi4327@gmail.com'),
      lower('createwithaarush@gmail.com'),
      lower('aaravraj.rudrakrit@gmail.com'),
      lower('skillmaxxing7@gmail.com')
    )
  ) <> 4 then
    raise exception 'Expected all four Supabase Auth users to exist; verify the account emails before running this migration.';
  end if;
end $$;

-- Assign accounts by their existing Supabase Auth email addresses.
insert into public.team_members(user_id,role,email,client_name)
select id,'owner',email,null from auth.users where lower(email)=lower('dhavaljoshi4327@gmail.com')
on conflict(user_id) do update set role=excluded.role, email=excluded.email, client_name=null;

insert into public.team_members(user_id,role,email,client_name)
select id,'editor',email,null from auth.users where lower(email) in (lower('createwithaarush@gmail.com'),lower('aaravraj.rudrakrit@gmail.com'))
on conflict(user_id) do update set role=excluded.role, email=excluded.email, client_name=null;

insert into public.team_members(user_id,role,email,client_name)
select id,'client',email,'SkillMaxxing' from auth.users where lower(email)=lower('skillmaxxing7@gmail.com')
on conflict(user_id) do update set role=excluded.role, email=excluded.email, client_name=excluded.client_name;

commit;

-- Verify all four accounts were found and assigned:
select u.email, tm.role, tm.client_name
from auth.users u join public.team_members tm on tm.user_id=u.id
where lower(u.email) in (
 lower('dhavaljoshi4327@gmail.com'),
 lower('createwithaarush@gmail.com'),
 lower('aaravraj.rudrakrit@gmail.com'),
 lower('skillmaxxing7@gmail.com')
)
order by tm.role, u.email;
