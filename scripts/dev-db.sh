#!/usr/bin/env bash
# =============================================================================
# Risk Studio v5 | Local database bootstrap
# Creates the database and the three least-privilege users from api/.env,
# applies migrations, grants, seeds and the catalogue. Safe to run again.
#
#   scripts/dev-db.sh           bootstrap or upgrade
#   scripts/dev-db.sh --reset   drop everything first
#   scripts/dev-db.sh --fixtures also load db/fixtures (fictitious feed data,
#                                development only)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/api/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/api/.env.example" "$ENV_FILE"
  # Local-only random passwords, never reused anywhere else.
  for key in DB_READ_PASSWORD DB_WRITE_PASSWORD DB_ADMIN_PASSWORD; do
    sed -i "s|^${key}=.*|${key}=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')|" "$ENV_FILE"
  done
  echo "Created api/.env with random local passwords."
fi

env_get() { grep -E "^$1=" "$ENV_FILE" | head -1 | cut -d= -f2-; }
DB_NAME="$(env_get DB_NAME)"

if ! mariadb -e 'SELECT 1' >/dev/null 2>&1; then
  echo "Starting MariaDB..."
  (service mariadb start || (mysqld_safe >/dev/null 2>&1 &)) >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do mariadb -e 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
fi

RESET=0; FIXTURES=0
for arg in "$@"; do
  case "$arg" in
    --reset) RESET=1 ;;
    --fixtures) FIXTURES=1 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ "$RESET" == 1 ]]; then
  echo "Dropping database ${DB_NAME}."
  mariadb -e "DROP DATABASE IF EXISTS \`${DB_NAME}\`;"
fi

mariadb <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'rs_admin'@'localhost';
CREATE USER IF NOT EXISTS 'rs_write'@'localhost';
CREATE USER IF NOT EXISTS 'rs_read'@'localhost';
ALTER USER 'rs_admin'@'localhost' IDENTIFIED BY '$(env_get DB_ADMIN_PASSWORD)';
ALTER USER 'rs_write'@'localhost' IDENTIFIED BY '$(env_get DB_WRITE_PASSWORD)';
ALTER USER 'rs_read'@'localhost'  IDENTIFIED BY '$(env_get DB_READ_PASSWORD)';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO 'rs_admin'@'localhost';
SQL

php "$ROOT/api/bin/migrate.php" --seed

# Grants last: column and view grants need the objects to exist.
sed "s/__DB__/${DB_NAME}/g" "$ROOT/db/grants.sql" | mariadb --default-character-set=utf8mb4

php "$ROOT/api/bin/import-catalogue.php"

if [[ "$FIXTURES" == 1 ]]; then
  for f in "$ROOT"/db/fixtures/*.sql; do
    echo "Loading development fixtures $(basename "$f")"
    mariadb --default-character-set=utf8mb4 "$DB_NAME" < "$f"
  done
fi
echo "Database ${DB_NAME} ready."
