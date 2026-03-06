#!/usr/bin/env bash
set -euo pipefail

backup_path="${1:-}"
if [[ -z "${backup_path}" ]]; then
  echo "Usage: scripts/backup_verify.sh <backup.sql>"
  exit 2
fi

if [[ ! -f "${backup_path}" ]]; then
  echo "Backup file not found: ${backup_path}"
  exit 2
fi

if [[ ! -s "${backup_path}" ]]; then
  echo "Backup file is empty: ${backup_path}"
  exit 1
fi

if ! head -n 5 "${backup_path}" | grep -q "PostgreSQL database dump"; then
  echo "Backup does not look like a pg_dump plain SQL file: ${backup_path}"
  exit 1
fi

echo "Backup file looks valid: ${backup_path}"

