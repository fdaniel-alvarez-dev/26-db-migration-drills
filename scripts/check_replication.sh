#!/usr/bin/env bash
set -euo pipefail

primary_id="$(docker compose ps -q postgres-primary)"
replica_id="$(docker compose ps -q postgres-replica)"

if [[ -z "${primary_id}" || -z "${replica_id}" ]]; then
  echo "Containers not found. Start the lab first:"
  echo "  make up"
  exit 2
fi

echo "Waiting for primary to accept connections..."
for _ in $(seq 1 60); do
  if docker exec -i "${primary_id}" psql -U app -d appdb -tAc "select 1" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "Waiting for replica to enter recovery mode..."
in_recovery=""
for _ in $(seq 1 60); do
  in_recovery="$(docker exec -i "${replica_id}" psql -U app -d appdb -tAc "select pg_is_in_recovery()" 2>/dev/null || true)"
  if [[ "${in_recovery}" == "t" ]]; then
    break
  fi
  sleep 1
done

if [[ "${in_recovery}" != "t" ]]; then
  echo "Replica is not in recovery mode. Replication is not configured/healthy."
  exit 1
fi

echo "Checking replication status on primary..."
docker exec -i "${primary_id}" psql -U app -d appdb -c "select application_name, state, sync_state, write_lag, flush_lag, replay_lag from pg_stat_replication;"

replica_streaming_count="$(docker exec -i "${primary_id}" psql -U app -d appdb -tAc \"select count(*) from pg_stat_replication where state = 'streaming'\" | tr -d '[:space:]')"
if [[ "${replica_streaming_count}" == "0" || -z "${replica_streaming_count}" ]]; then
  echo "Primary does not report any streaming replicas (pg_stat_replication)."
  exit 1
fi

echo
echo "Checking replica is in recovery mode..."
docker exec -i "${replica_id}" psql -U app -d appdb -c "select pg_is_in_recovery();"
