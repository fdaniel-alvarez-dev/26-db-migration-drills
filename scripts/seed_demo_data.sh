#!/usr/bin/env bash
set -euo pipefail

primary_id="$(docker compose ps -q postgres-primary)"
if [[ -z "${primary_id}" ]]; then
  echo "Postgres primary container not found. Run: make up"
  exit 2
fi

echo "Seeding demo data into appdb..."
docker exec -i "${primary_id}" psql -U app -d appdb <<'SQL'
create table if not exists demo_items (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  payload text not null
);

insert into demo_items (payload)
select 'demo-payload-' || g::text
from generate_series(1, 10) as g;

select count(*) as demo_items_count from demo_items;
SQL

