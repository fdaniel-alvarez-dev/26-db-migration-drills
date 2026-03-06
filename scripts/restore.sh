#!/usr/bin/env bash
set -euo pipefail

latest="$(ls -1 artifacts/backups/*.sql 2>/dev/null | tail -n 1 || true)"
if [[ -z "${latest}" ]]; then
  echo "No backups found under artifacts/backups/. Run: make backup"
  exit 1
fi

echo "Restoring latest backup: ${latest}"
primary_id="$(docker compose ps -q postgres-primary)"
if [[ -z "${primary_id}" ]]; then
  echo "Postgres primary container not found. Run: make up"
  exit 2
fi

verify_db="appdb_verify"

echo "Restoring latest backup into isolated database '${verify_db}': ${latest}"
docker exec -i "${primary_id}" psql -U app -d postgres -v ON_ERROR_STOP=1 -c "drop database if exists ${verify_db};"
docker exec -i "${primary_id}" psql -U app -d postgres -v ON_ERROR_STOP=1 -c "create database ${verify_db};"
docker exec -i "${primary_id}" psql -U app -d "${verify_db}" -v ON_ERROR_STOP=1 < "${latest}"

echo "Verifying restored data..."
docker exec -i "${primary_id}" psql -U app -d "${verify_db}" -v ON_ERROR_STOP=1 -c "select count(*) as demo_items_count from demo_items;"

echo "Restore verification complete."
