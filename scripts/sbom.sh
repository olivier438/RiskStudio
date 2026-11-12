#!/usr/bin/env bash
# =============================================================================
# Risk Studio v5 | Software Bill of Materials (CycloneDX JSON), CRA Annex I II.1
#
#   scripts/sbom.sh    writes dist/sbom/riskstudio-web.cdx.json
#                             dist/sbom/riskstudio-api.cdx.json
#
# Front end: npm's built-in CycloneDX generator. The whole lockfile is listed
# because the static build bundles parts of its "devDependencies" (Svelte and
# SvelteKit runtimes). Back end: built from composer.lock.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/sbom"
mkdir -p "$OUT"

# SvelteKit 3 generates node_modules/$app (types only, not a package): npm
# rejects its name, so it is set aside during the run and always restored.
APP_TYPES="$ROOT/web/node_modules/\$app"
PARKED="$ROOT/web/.sbom-parked-app"
restore() { [[ -d "$PARKED" ]] && mv "$PARKED" "$APP_TYPES" || true; }
trap restore EXIT
[[ -d "$APP_TYPES" ]] && mv "$APP_TYPES" "$PARKED"

(cd "$ROOT/web" && npm sbom --sbom-format cyclonedx --sbom-type application) > "$OUT/riskstudio-web.cdx.json"
php "$ROOT/scripts/sbom-composer.php" "$ROOT/api" > "$OUT/riskstudio-api.cdx.json"

for f in "$OUT"/*.cdx.json; do
  php -r '$d = json_decode(file_get_contents($argv[1]), true);
          if (($d["bomFormat"] ?? "") !== "CycloneDX") { fwrite(STDERR, "Invalid SBOM {$argv[1]}\n"); exit(1); }
          printf("  %-28s CycloneDX %s, %d components\n", basename($argv[1]), $d["specVersion"], count($d["components"] ?? []));' "$f"
done
