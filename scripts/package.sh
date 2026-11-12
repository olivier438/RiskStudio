#!/usr/bin/env bash
# =============================================================================
# Risk Studio v5 | Release package for Infomaniak shared hosting
#
#   scripts/package.sh [APP_DIR_FROM_WEB]
#
# Produces dist/release/ and dist/riskstudio-<version>.tar.gz:
#
#   app/   upload OUTSIDE the web root (e.g. ~/riskstudio-app)
#          PHP sources, production autoloader, bin/, db/ (migrations, seeds,
#          catalogue, rules), SBOM. Never contains .env, tests or fixtures.
#   www/   upload INTO the web root of the site
#          static front end + api/index.php, a stub that loads app/
#
# APP_DIR_FROM_WEB: path of app/ seen from the web root, default
# "../riskstudio-app" (site in ~/sites/riskstudio, app in ~/sites/riskstudio-app).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_REL="${1:-../riskstudio-app}"
OUT="$ROOT/dist/release"
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"

if [[ ! "$APP_REL" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "Invalid APP_DIR_FROM_WEB: $APP_REL" >&2
  exit 2
fi

echo "Packaging Risk Studio $VERSION"
rm -rf "$OUT"
mkdir -p "$OUT/app" "$OUT/www/api"

# ---- front end ---------------------------------------------------------------
(cd "$ROOT/web" && npm run build >/dev/null)
cp -R "$ROOT/web/build/." "$OUT/www/"

# ---- application -------------------------------------------------------------
cp -R "$ROOT/api/src" "$ROOT/api/bin" "$ROOT/api/public" "$OUT/app/"
cp "$ROOT/api/composer.json" "$ROOT/api/composer.lock" "$ROOT/api/.env.example" "$OUT/app/"
mkdir -p "$OUT/app/db"
cp -R "$ROOT/db/migrations" "$ROOT/db/seeds" "$ROOT/db/catalogue" "$ROOT/db/rules" "$OUT/app/db/"
cp "$ROOT/db/grants.sql" "$OUT/app/db/"
# No runtime dependency: --no-dev only builds the optimised autoloader.
(cd "$OUT/app" && composer install --no-dev --no-interaction --no-progress --classmap-authoritative --quiet)

# If app/ ever lands under the web root by mistake, Apache serves nothing.
cat > "$OUT/app/.htaccess" <<'HTACCESS'
Require all denied
HTACCESS

# ---- API entry point in the web root -------------------------------------------
cp "$ROOT/api/public/.htaccess" "$OUT/www/api/.htaccess"
cat > "$OUT/www/api/index.php" <<PHP
<?php
// Risk Studio API entry point. The application lives outside the web root.
\$appRoot = realpath(__DIR__ . '/../${APP_REL}');
if (\$appRoot === false || !is_file(\$appRoot . '/public/index.php')) {
    http_response_code(503);
    header('Content-Type: application/json');
    echo '{"error":{"code":"unavailable","message":"Application not installed."}}';
    exit;
}
putenv('RS_APP_ROOT=' . \$appRoot);
require \$appRoot . '/public/index.php';
PHP

# ---- SBOM (when the CycloneDX tools are available) ------------------------------
if [[ -f "$ROOT/dist/sbom/riskstudio-web.cdx.json" ]]; then
  mkdir -p "$OUT/app/sbom"
  cp "$ROOT"/dist/sbom/*.cdx.json "$OUT/app/sbom/"
fi

printf '%s\n%s\n' "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUT/app/VERSION"

# ---- safety checks -----------------------------------------------------------------
leaks="$(find "$OUT" \( -name '.env' -o -name 'phpunit*' -o -path '*/tests/*' -o -path '*/fixtures/*' \) -print)"
if [[ -n "$leaks" ]]; then
  echo "Refusing to package development files:" >&2
  echo "$leaks" >&2
  exit 1
fi

tar -C "$OUT" -czf "$ROOT/dist/riskstudio-${VERSION}.tar.gz" app www
echo "Done: dist/release/{app,www} and dist/riskstudio-${VERSION}.tar.gz"
du -sh "$OUT/app" "$OUT/www" | sed 's/^/  /'
