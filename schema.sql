-- Boule-Plattform: Vereine, Projektadministratoren, Projekte
-- Im Supabase SQL Editor komplett ausführen. Danach die letzte Zeile (Superadmin) mit deiner E-Mail anpassen.

create table if not exists vereine (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  created_at timestamptz not null default now()
);

create table if not exists superadmins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists verein_admins (
  verein_id uuid not null references vereine(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  primary key (verein_id, user_id)
);

create table if not exists projekte (
  id uuid primary key default gen_random_uuid(),
  verein_id uuid not null references vereine(id) on delete cascade,
  name text not null,
  slug text not null,
  typ text not null check (typ in ('kreisel', 'supermelee')),
  daten jsonb not null default '{}',
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (verein_id, slug)
);

-- Hilfsfunktionen für die Rechteprüfung
create or replace function is_superadmin() returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from superadmins where user_id = auth.uid())
$$;

create or replace function is_verein_admin(vid uuid) returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from verein_admins where verein_id = vid and user_id = auth.uid())
$$;

-- Zeilenrechte (Row Level Security)
alter table vereine enable row level security;
alter table superadmins enable row level security;
alter table verein_admins enable row level security;
alter table projekte enable row level security;

drop policy if exists vereine_lesen on vereine;
drop policy if exists vereine_super on vereine;
create policy vereine_lesen on vereine for select using (true);
create policy vereine_super on vereine for all to authenticated
  using (is_superadmin()) with check (is_superadmin());

drop policy if exists sa_lesen on superadmins;
create policy sa_lesen on superadmins for select to authenticated
  using (user_id = auth.uid());

drop policy if exists va_lesen on verein_admins;
drop policy if exists va_super on verein_admins;
create policy va_lesen on verein_admins for select to authenticated
  using (is_superadmin() or user_id = auth.uid());
create policy va_super on verein_admins for all to authenticated
  using (is_superadmin()) with check (is_superadmin());

drop policy if exists projekte_lesen on projekte;
drop policy if exists projekte_admin on projekte;
create policy projekte_lesen on projekte for select using (true);
create policy projekte_admin on projekte for all to authenticated
  using (is_superadmin() or is_verein_admin(verein_id))
  with check (is_superadmin() or is_verein_admin(verein_id));

-- Zugriff auf die Tabellen über die API
grant select on vereine, projekte to anon, authenticated;
grant insert, update, delete on vereine, projekte to authenticated;
grant select on superadmins, verein_admins to authenticated;
grant insert, update, delete on verein_admins to authenticated;

-- Projektadmin per E-Mail zuordnen (nur Superadmin)
create or replace function admin_hinzufuegen(vid uuid, mail text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if not is_superadmin() then
    raise exception 'Nur der Superadministrator darf das.';
  end if;
  select id into uid from auth.users where lower(email) = lower(trim(mail));
  if uid is null then
    raise exception 'Kein Benutzer mit dieser E-Mail. Bitte zuerst im Supabase-Dashboard einladen.';
  end if;
  insert into verein_admins (verein_id, user_id, email)
  values (vid, uid, lower(trim(mail)))
  on conflict do nothing;
end
$$;

revoke all on function admin_hinzufuegen(uuid, text) from public, anon;
grant execute on function admin_hinzufuegen(uuid, text) to authenticated;

-- Die alte Tabelle aus der ersten Version wird nicht mehr gebraucht (optional):
-- drop table if exists turnier;

-- Dich zum Superadministrator machen: E-Mail durch deine Login-Adresse ersetzen.
insert into superadmins (user_id)
select id from auth.users where email = 'DEINE@EMAIL.DE'
on conflict do nothing;
