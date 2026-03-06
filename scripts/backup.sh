#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/backups
ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="artifacts/backups/appdb-${ts}.sql"

primary_id="$(docker compose ps -q postgres-primary)"
if [[ -z "${primary_id}" ]]; then
  echo "Postgres primary container not found. Run: make up"
  exit 2
fi

echo "Creating logical backup to ${out}..."
docker exec -i "${primary_id}" pg_dump -U app -d appdb > "${out}"

echo "Backup created."
