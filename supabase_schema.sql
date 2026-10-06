-- ==================== API KEYS ====================
create table if not exists cg_api_keys (
  id bigserial primary key,
  key_code text unique not null,
  status text default 'available' check (status in ('available','used','blocked')),
  used_by_telegram text,
  used_by_user_id uuid,
  used_at timestamptz,
  note text,
  created_at timestamptz default now()
);

create index if not exists idx_keys_code on cg_api_keys(key_code);
create index if not exists idx_keys_status on cg_api_keys(status);

-- ==================== USERS ====================
create table if not exists cg_users (
  id uuid primary key default gen_random_uuid(),
  telegram_id bigint unique,
  telegram_username text unique,
  full_name text,
  phone text,
  created_at timestamptz default now(),
  verified boolean default false
);

-- ==================== VERIFICATIONS ====================
create table if not exists cg_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references cg_users(id) on delete cascade,
  telegram_id bigint,
  telegram_username text,
  api_key text,
  site text not null check (site in ('facebook','tiktok','instagram')),
  account text not null,
  phone text not null,
  selfie_path text not null,
  selfie_hash text not null,
  status text default 'pending' check (status in ('pending','success','failed','blocked')),
  error_msg text,
  cookie_path text,
  cookie_count int,
  download_token text unique,
  token_expires_at timestamptz,
  ip_address text,
  user_ip text,
  proxy_used text,
  exit_ip text,
  exit_ip_country text,
  exit_ip_isp text,
  exit_ip_is_dc boolean default false,
  mode text default 'auto',
  user_agent text,
  created_at timestamptz default now(),
  completed_at timestamptz
);

create index if not exists idx_verif_user on cg_verifications(user_id);
create index if not exists idx_verif_token on cg_verifications(download_token);
create index if not exists idx_verif_username on cg_verifications(telegram_username);

-- ==================== AUDIT ====================
create table if not exists cg_audit_log (
  id bigserial primary key,
  telegram_id bigint,
  telegram_username text,
  action text not null,
  detail jsonb,
  ip text,
  created_at timestamptz default now()
);

-- ==================== RLS ====================
alter table cg_api_keys enable row level security;
alter table cg_users enable row level security;
alter table cg_verifications enable row level security;
alter table cg_audit_log enable row level security;

drop policy if exists "svc keys" on cg_api_keys;
drop policy if exists "svc users" on cg_users;
drop policy if exists "svc verif" on cg_verifications;
drop policy if exists "svc audit" on cg_audit_log;

create policy "svc keys" on cg_api_keys for all using (auth.role() = 'service_role');
create policy "svc users" on cg_users for all using (auth.role() = 'service_role');
create policy "svc verif" on cg_verifications for all using (auth.role() = 'service_role');
create policy "svc audit" on cg_audit_log for all using (auth.role() = 'service_role');

-- ==================== HÀM IMPORT KEY ====================
-- Sau khi import xong, chạy lệnh này để check
-- select count(*), status from cg_api_keys group by status;
