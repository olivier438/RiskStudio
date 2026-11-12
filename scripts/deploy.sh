#!/usr/bin/env bash
# =============================================================================
# Risk Studio v5 | Deployment to Infomaniak shared hosting over SSH
#
# Runs from GitHub Actions (.github/workflows/deploy.yml) or from a computer
# with SSH access to the hosting. Requires dist/release (scripts/package.sh).
#
# Configuration, from the environment (never from the repository):
#   DEPLOY_HOST      SSH host, e.g. xxxx.ftp.infomaniak.com
#   DEPLOY_USER      SSH user
#   DEPLOY_PORT      SSH port (default 22)
#   DEPLOY_APP_DIR   application folder, OUTSIDE the web root (absolute path)
#   DEPLOY_WEB_DIR   web root of the site (absolute path)
#   DEPLOY_URL       public URL, e.g. https://riskstudio.example.org
#   DEPLOY_PHP       PHP CLI on the hosting (default php)
#
# The production .env lives only on the server, in DEPLOY_APP_DIR: this script
# never creates, reads or overwrites it.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REL="$ROOT/dist/release"
: "${DEPLOY_HOST:?missing}" "${DEPLOY_USER:?missing}" "${DEPLOY_APP_DIR:?missing}" "${DEPLOY_WEB_DIR:?missing}" "${DEPLOY_URL:?missing}"
PORT="${DEPLOY_PORT:-22}"
PHP="${DEPLOY_PHP:-php}"
TARGET="${DEPLOY_USER}@${DEPLOY_HOST}"
SSH=(ssh -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=yes)
RSYNC=(rsync -rlptz --checksum -e "ssh -p $PORT -o BatchMode=yes -o StrictHostKeyChecking=yes")

for path in "$DEPLOY_APP_DIR" "$DEPLOY_WEB_DIR"; do
  if [[ ! "$path" =~ ^/[A-Za-z0-9._/-]+$ || "$path" == "/" ]]; then
    echo "Refusing unsafe remote path: $path" >&2
    exit 2
  fi
done
[[ -d "$REL/app" && -d "$REL/www" ]] || { echo "Run scripts/package.sh first." >&2; exit 2; }

step() { printf '\n==> %s\n' "$*"; }
remote() { "${SSH[@]}" "$TARGET" "$@"; }

step "Preflight"
remote "set -e
  test -f '$DEPLOY_APP_DIR/.env' || { echo 'Missing $DEPLOY_APP_DIR/.env: see docs/deploy-infomaniak.md, first installation.' >&2; exit 3; }
  test -d '$DEPLOY_WEB_DIR' || { echo 'Missing web root $DEPLOY_WEB_DIR' >&2; exit 3; }
  $PHP -r 'exit(PHP_VERSION_ID >= 80200 && extension_loaded(\"pdo_mysql\") ? 0 : 1);' || { echo 'PHP 8.2+ with pdo_mysql required' >&2; exit 3; }
  $PHP -v | head -1"

step "Backup of the current application"
remote "if [ -d '$DEPLOY_APP_DIR/src' ]; then rm -rf '$DEPLOY_APP_DIR.previous' && cp -a '$DEPLOY_APP_DIR' '$DEPLOY_APP_DIR.previous'; echo saved; else echo 'first deployment'; fi"

step "Application"
# --delete keeps the folder identical to the package, except the server .env.
"${RSYNC[@]}" --delete --exclude='/.env' "$REL/app/" "$TARGET:$DEPLOY_APP_DIR/"
remote "chmod 600 '$DEPLOY_APP_DIR/.env'"

step "Database: migrations, seeds, catalogue"
if ! remote "cd '$DEPLOY_APP_DIR' && $PHP bin/migrate.php --seed && $PHP bin/import-catalogue.php"; then
  echo "Database step failed. The previous application is in $DEPLOY_APP_DIR.previous." >&2
  echo "Rollback: ssh $TARGET \"rm -rf '$DEPLOY_APP_DIR' && mv '$DEPLOY_APP_DIR.previous' '$DEPLOY_APP_DIR'\"" >&2
  exit 4
fi

step "Static site"
# No --delete on the web root (it may hold other files, e.g. .well-known);
# only the fingerprinted bundle folder is mirrored exactly.
"${RSYNC[@]}" --exclude='/_app/' "$REL/www/" "$TARGET:$DEPLOY_WEB_DIR/"
"${RSYNC[@]}" --delete "$REL/www/_app/" "$TARGET:$DEPLOY_WEB_DIR/_app/"

step "Smoke test"
health="$(curl -fsS --max-time 20 "$DEPLOY_URL/api/v1/health")" || { echo "Health endpoint unreachable" >&2; exit 5; }
echo "$health"
grep -q '"status":"ok"' <<<"$health" || { echo "API not healthy" >&2; exit 5; }
curl -fsS --max-time 20 -o /dev/null "$DEPLOY_URL/" && echo "Home page OK"
curl -fsS --max-time 20 "$DEPLOY_URL/api/v1/risks?per_page=1" | grep -q '"total"' && echo "Catalogue OK"

step "Deployed $(head -1 "$REL/app/VERSION") to $DEPLOY_URL"
