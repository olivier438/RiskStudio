# Risk Studio v5 | Developer commands
# Requirements: PHP 8.2+ (pdo_mysql), Composer, MariaDB 10.6+, Node.js 22+ (build only).

.PHONY: help setup db db-reset fixtures catalogue api web dev test check build preview

help: ## List commands
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  make %-10s %s\n", $$1, $$2}'

setup: ## Install PHP and front-end dependencies
	cd api && composer install
	cd web && npm ci

db: ## Create or upgrade the local database (users, migrations, grants, seeds)
	scripts/dev-db.sh

db-reset: ## Drop and rebuild the local database
	scripts/dev-db.sh --reset

fixtures: ## Load fictitious feed data for UI development (never in production)
	scripts/dev-db.sh --fixtures

catalogue: ## Validate then import db/catalogue (risks, controls, crosswalk)
	php api/bin/import-catalogue.php --dry-run && php api/bin/import-catalogue.php

api: ## Run the PHP API on http://127.0.0.1:8080/api
	php -S 127.0.0.1:8080 api/public/index.php

web: ## Run the Svelte dev server (proxies /api to :8080)
	cd web && npm run dev

dev: ## Run API and front end together
	@trap 'kill 0' EXIT; php -S 127.0.0.1:8080 api/public/index.php & cd web && npm run dev

test: ## PHP unit + integration tests
	cd api && vendor/bin/phpunit

check: test ## Tests + front-end type check
	cd web && npm run check

build: ## Build the static front end into web/build
	cd web && npm run build

preview: build ## Serve the production build + API like Apache would, on :8090
	php -S 127.0.0.1:8090 scripts/preview-router.php
